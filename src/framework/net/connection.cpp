/*
 * Copyright (c) 2010-2017 OTClient <https://github.com/edubart/otclient>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "connection.h"

#include <framework/core/application.h>
#include <framework/core/eventdispatcher.h>
#include <boost/asio.hpp>
#include <array>
#include <sstream>
#include <framework/util/crypt.h>
#include <framework/util/stats.h>
#include <framework/util/extras.h>
#include <chrono>

asio::io_service g_ioService;
std::list<std::shared_ptr<asio::streambuf>> Connection::m_outputStreams;
SocksProxyConfig g_socksProxy;
HttpProxyConfig g_httpProxy;

Connection::Connection() :
        m_readTimer(g_ioService),
        m_writeTimer(g_ioService),
        m_delayedWriteTimer(g_ioService),
        m_resolver(g_ioService),
        m_socket(g_ioService)
{
    m_connected = false;
    m_connecting = false;
}

Connection::~Connection()
{
    VALIDATE(!g_app.isTerminated());
    close();
}

void Connection::poll()
{
    AutoStat s(STATS_MAIN, "PollConnection");
    // reset must always be called prior to poll
    g_ioService.reset();
    g_ioService.poll();
}

void Connection::terminate()
{
    g_ioService.stop();
    m_outputStreams.clear();
}

void Connection::close()
{
    if(!m_connected && !m_connecting)
        return;

    // flush send data before disconnecting on clean connections
    if(m_connected && !m_error && m_outputStream)
        internal_write();

    m_connecting = false;
    m_connected = false;
    m_connectCallback = nullptr;
    m_errorCallback = nullptr;
    m_recvCallback = nullptr;

    m_resolver.cancel();
    m_readTimer.cancel();
    m_writeTimer.cancel();
    m_delayedWriteTimer.cancel();

    if(m_socket.is_open()) {
        boost::system::error_code ec;
        m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        m_socket.close();
    }
}

void Connection::connect(const std::string& host, uint16 port, const std::function<void()>& connectCallback)
{
    m_connected = false;
    m_connecting = true;
    m_error.clear();
    m_connectCallback = connectCallback;

    // If a SOCKS proxy is configured, connect synchronously through it (supports SOCKS4 and SOCKS5 with optional auth)
    if(!g_socksProxy.host.empty() && g_socksProxy.port > 0) {
        try {
            // resolve proxy
            asio::ip::tcp::resolver::query proxyQuery(g_socksProxy.host, stdext::unsafe_cast<std::string>(g_socksProxy.port));
            auto proxyEndpoint = m_resolver.resolve(proxyQuery);
            boost::asio::connect(m_socket, proxyEndpoint);

            if(g_socksProxy.version == 4) {
                // SOCKS4
                asio::ip::tcp::resolver::query dstQuery(host, stdext::unsafe_cast<std::string>(port));
                auto dstIt = m_resolver.resolve(dstQuery);
                auto dstEndpoint = *dstIt;
                if(!dstEndpoint.endpoint().address().is_v4()) {
                    throw std::runtime_error("SOCKS4: only IPv4 addresses supported");
                }
                auto addrBytes = dstEndpoint.endpoint().address().to_v4().to_bytes();
                std::vector<uint8_t> req;
                req.push_back(0x04); // VN
                req.push_back(0x01); // CONNECT
                req.push_back((uint8_t)((port >> 8) & 0xFF));
                req.push_back((uint8_t)(port & 0xFF));
                req.insert(req.end(), addrBytes.begin(), addrBytes.end());
                if(!g_socksProxy.user.empty()) {
                    req.insert(req.end(), g_socksProxy.user.begin(), g_socksProxy.user.end());
                }
                req.push_back(0x00); // end of userid
                boost::asio::write(m_socket, boost::asio::buffer(req));

                std::array<uint8_t,8> resp;
                boost::asio::read(m_socket, boost::asio::buffer(resp));
                if(resp[1] != 0x5A) {
                    throw std::runtime_error("SOCKS4 connect failed");
                }
            } else {
                // SOCKS5 greeting: allow no-auth and username/password
                std::vector<uint8_t> greeting;
                greeting.push_back(0x05);
                if(g_socksProxy.user.empty()) {
                    greeting.push_back(0x01);
                    greeting.push_back(0x00); // no auth
                } else {
                    greeting.push_back(0x02);
                    greeting.push_back(0x00); // no auth
                    greeting.push_back(0x02); // username/password
                }
                boost::asio::write(m_socket, boost::asio::buffer(greeting));

                std::array<uint8_t,2> greetResp;
                boost::asio::read(m_socket, boost::asio::buffer(greetResp));
                if(greetResp[0] != 0x05) {
                    throw std::runtime_error("SOCKS5 handshake failed");
                }
                if(greetResp[1] == 0x02) {
                    // username/password auth
                    std::vector<uint8_t> auth;
                    auth.push_back(0x01);
                    auth.push_back((uint8_t)g_socksProxy.user.size());
                    auth.insert(auth.end(), g_socksProxy.user.begin(), g_socksProxy.user.end());
                    auth.push_back((uint8_t)g_socksProxy.pass.size());
                    auth.insert(auth.end(), g_socksProxy.pass.begin(), g_socksProxy.pass.end());
                    boost::asio::write(m_socket, boost::asio::buffer(auth));
                    std::array<uint8_t,2> authResp;
                    boost::asio::read(m_socket, boost::asio::buffer(authResp));
                    if(authResp[1] != 0x00) {
                        throw std::runtime_error("SOCKS5 auth failed");
                    }
                } else if(greetResp[1] != 0x00) {
                    throw std::runtime_error("SOCKS5 no acceptable auth");
                }

                // Resolve destination
                asio::ip::tcp::resolver::query dstQuery(host, stdext::unsafe_cast<std::string>(port));
                auto dstIt = m_resolver.resolve(dstQuery);
                auto dstEndpoint = *dstIt;
                if(!dstEndpoint.endpoint().address().is_v4()) {
                    throw std::runtime_error("SOCKS5: only IPv4 addresses supported");
                }
                auto addrBytes = dstEndpoint.endpoint().address().to_v4().to_bytes();

                // SOCKS5 CONNECT
                std::array<uint8_t,10> connectReq;
                connectReq[0] = 0x05;
                connectReq[1] = 0x01; // CONNECT
                connectReq[2] = 0x00; // RSV
                connectReq[3] = 0x01; // IPv4
                connectReq[4] = addrBytes[0];
                connectReq[5] = addrBytes[1];
                connectReq[6] = addrBytes[2];
                connectReq[7] = addrBytes[3];
                connectReq[8] = (uint8_t)((port >> 8) & 0xFF);
                connectReq[9] = (uint8_t)(port & 0xFF);

                boost::asio::write(m_socket, boost::asio::buffer(connectReq));

                std::array<uint8_t,10> connectResp;
                boost::asio::read(m_socket, boost::asio::buffer(connectResp));
                if(connectResp[1] != 0x00) {
                    throw std::runtime_error("SOCKS5 CONNECT failed");
                }
            }

            // success - configure socket for async operations
            m_readTimer.cancel();
            m_writeTimer.cancel();
            m_delayedWriteTimer.cancel();
            
            boost::asio::ip::tcp::no_delay option(true);
            m_socket.set_option(option);
            boost::system::error_code ecc;
            m_socket.set_option(boost::asio::socket_base::send_buffer_size(524288), ecc);
            m_socket.set_option(boost::asio::socket_base::receive_buffer_size(524288), ecc);
            
            // Set socket to non-blocking for async operations
            m_socket.non_blocking(true, ecc);
            
            m_connected = true;
            m_connecting = false;
            m_activityTimer.restart();

            // Schedule callback on dispatcher to maintain async flow
            g_dispatcher.addEvent([this]() {
                if(m_connectCallback)
                    m_connectCallback();
            });
            return;
        } catch(std::exception& e) {
            m_error = boost::system::errc::make_error_code(boost::system::errc::connection_refused);
            g_logger.error(stdext::format("SOCKS connect failed (%s:%d v%d): %s", g_socksProxy.host, g_socksProxy.port, g_socksProxy.version, e.what()));
            if(m_errorCallback)
                m_errorCallback(m_error);
            m_connecting = false;
            return;
        }
    }

    // If an HTTP CONNECT proxy is configured, connect synchronously through it (optional Basic auth)
    if(!g_httpProxy.host.empty() && g_httpProxy.port > 0) {
        try {
            asio::ip::tcp::resolver::query proxyQuery(g_httpProxy.host, stdext::unsafe_cast<std::string>(g_httpProxy.port));
            auto proxyEndpoint = m_resolver.resolve(proxyQuery);
            boost::asio::connect(m_socket, proxyEndpoint);

            std::ostringstream req;
            req << "CONNECT " << host << ":" << port << " HTTP/1.1\r\n";
            req << "Host: " << host << ":" << port << "\r\n";
            req << "Proxy-Connection: Keep-Alive\r\n";
            if(!g_httpProxy.user.empty()) {
                std::string token = g_httpProxy.user + ":" + g_httpProxy.pass;
                std::string b64 = g_crypt.base64Encode(token);
                req << "Proxy-Authorization: Basic " << b64 << "\r\n";
            }
            req << "\r\n";
            auto reqStr = req.str();
            boost::asio::write(m_socket, boost::asio::buffer(reqStr));

            boost::asio::streambuf respBuf;
            boost::asio::read_until(m_socket, respBuf, "\r\n\r\n");
            std::istream respStream(&respBuf);
            std::string httpVersion;
            unsigned int statusCode;
            std::string statusMessage;
            respStream >> httpVersion >> statusCode;
            std::getline(respStream, statusMessage);
            if(!respStream || httpVersion.substr(0,5) != "HTTP/" || statusCode != 200) {
                throw std::runtime_error("HTTP CONNECT failed");
            }

            m_readTimer.cancel();
            m_writeTimer.cancel();
            m_delayedWriteTimer.cancel();
            
            boost::asio::ip::tcp::no_delay option(true);
            m_socket.set_option(option);
            boost::system::error_code ecc;
            m_socket.set_option(boost::asio::socket_base::send_buffer_size(524288), ecc);
            m_socket.set_option(boost::asio::socket_base::receive_buffer_size(524288), ecc);
            
            // Set socket to non-blocking for async operations
            m_socket.non_blocking(true, ecc);
            
            m_connected = true;
            m_connecting = false;
            m_activityTimer.restart();

            // Schedule callback on dispatcher to maintain async flow
            g_dispatcher.addEvent([this]() {
                if(m_connectCallback)
                    m_connectCallback();
            });
            return;
        } catch(std::exception& e) {
            m_error = boost::system::errc::make_error_code(boost::system::errc::connection_refused);
            g_logger.error(stdext::format("HTTP CONNECT failed (%s:%d): %s", g_httpProxy.host, g_httpProxy.port, e.what()));
            if(m_errorCallback)
                m_errorCallback(m_error);
            m_connecting = false;
            return;
        }
    }

    asio::ip::tcp::resolver::query query(host, stdext::unsafe_cast<std::string>(port));
    m_resolver.async_resolve(query, std::bind(&Connection::onResolve, asConnection(), std::placeholders::_1, std::placeholders::_2));

    m_readTimer.cancel();
    m_readTimer.expires_from_now(std::chrono::seconds(READ_TIMEOUT));
    m_readTimer.async_wait(std::bind(&Connection::onTimeout, asConnection(), std::placeholders::_1));
}

void Connection::internal_connect(asio::ip::basic_resolver<asio::ip::tcp>::iterator endpointIterator)
{
    m_socket.async_connect(*endpointIterator, std::bind(&Connection::onConnect, asConnection(), std::placeholders::_1));

    m_readTimer.cancel();
    m_readTimer.expires_from_now(std::chrono::seconds(READ_TIMEOUT));
    m_readTimer.async_wait(std::bind(&Connection::onTimeout, asConnection(), std::placeholders::_1));
}

void Connection::write(uint8* buffer, size_t size)
{
    if(!m_connected)
        return;

    // we can't send the data right away, otherwise we could create tcp congestion
    if(!m_outputStream) {
        if(!m_outputStreams.empty()) {
            m_outputStream = m_outputStreams.front();
            m_outputStreams.pop_front();
        } else
            m_outputStream = std::make_shared<asio::streambuf>();

        m_delayedWriteTimer.cancel();
        m_delayedWriteTimer.expires_from_now(std::chrono::milliseconds(0));
        m_delayedWriteTimer.async_wait(std::bind(&Connection::onCanWrite, asConnection(), std::placeholders::_1));
    }

    std::ostream os(m_outputStream.get());
    os.write((const char*)buffer, size);
    os.flush();
}

void Connection::internal_write()
{
    if(!m_connected)
        return;

    std::shared_ptr<asio::streambuf> outputStream = m_outputStream;
    m_outputStream = nullptr;

    asio::async_write(m_socket,
                      *outputStream,
                      std::bind(&Connection::onWrite, asConnection(), std::placeholders::_1, std::placeholders::_2, outputStream));

    m_writeTimer.cancel();
    m_writeTimer.expires_from_now(std::chrono::seconds(WRITE_TIMEOUT));
    m_writeTimer.async_wait(std::bind(&Connection::onTimeout, asConnection(), std::placeholders::_1));
}

void Connection::read(uint32 bytes, const RecvCallback& callback)
{
    if(!m_connected)
        return;

    m_recvCallback = callback;

    asio::async_read(m_socket,
                     asio::mutable_buffer(m_inputStream.prepare(bytes)),
                     std::bind(&Connection::onRecv, asConnection(), std::placeholders::_1, std::placeholders::_2));

    m_readTimer.cancel();
    m_readTimer.expires_from_now(std::chrono::seconds(READ_TIMEOUT));
    m_readTimer.async_wait(std::bind(&Connection::onTimeout, asConnection(), std::placeholders::_1));
}

void Connection::read_until(const std::string& what, const RecvCallback& callback)
{
    if(!m_connected)
        return;

    m_recvCallback = callback;

    asio::async_read_until(m_socket,
                           m_inputStream,
                           what.c_str(),
                           std::bind(&Connection::onRecv, asConnection(), std::placeholders::_1, std::placeholders::_2));

    m_readTimer.cancel();
    m_readTimer.expires_from_now(std::chrono::seconds(READ_TIMEOUT));
    m_readTimer.async_wait(std::bind(&Connection::onTimeout, asConnection(), std::placeholders::_1));
}

void Connection::read_some(const RecvCallback& callback)
{
    if(!m_connected)
        return;

    m_recvCallback = callback;

    m_socket.async_read_some(asio::mutable_buffer(m_inputStream.prepare(RECV_BUFFER_SIZE)),
                             std::bind(&Connection::onRecv, asConnection(), std::placeholders::_1, std::placeholders::_2));

    m_readTimer.cancel();
    m_readTimer.expires_from_now(std::chrono::seconds(READ_TIMEOUT));
    m_readTimer.async_wait(std::bind(&Connection::onTimeout, asConnection(), std::placeholders::_1));
}

void Connection::onResolve(const boost::system::error_code& error, asio::ip::basic_resolver<asio::ip::tcp>::iterator endpointIterator)
{
    m_readTimer.cancel();

    if(error == asio::error::operation_aborted)
        return;

    if(!error)
        internal_connect(endpointIterator);
    else
        handleError(error);
}

void Connection::onConnect(const boost::system::error_code& error)
{
    m_readTimer.cancel();
    m_activityTimer.restart();

    if(error == asio::error::operation_aborted)
        return;

    if(!error) {
        m_connected = true;

        // disable nagle's algorithm, this make the game play smoother
        boost::asio::ip::tcp::no_delay option(true);
        m_socket.set_option(option);
        boost::system::error_code ecc;
        m_socket.set_option(boost::asio::socket_base::send_buffer_size(524288), ecc);
        m_socket.set_option(boost::asio::socket_base::receive_buffer_size(524288), ecc);

        if(m_connectCallback)
            m_connectCallback();
    } else
        handleError(error);

    m_connecting = false;
}

void Connection::onCanWrite(const boost::system::error_code& error)
{
    m_delayedWriteTimer.cancel();

    if(error == asio::error::operation_aborted)
        return;

    if(m_connected)
        internal_write();
}

void Connection::onWrite(const boost::system::error_code& error, size_t writeSize, std::shared_ptr<asio::streambuf> outputStream)
{
    m_writeTimer.cancel();

    if(error == asio::error::operation_aborted)
        return;

    // free output stream and store for using it again later
    outputStream->consume(outputStream->size());
    m_outputStreams.push_back(outputStream);

    if(m_connected && error)
        handleError(error);
}

void Connection::onRecv(const boost::system::error_code& error, size_t recvSize)
{
    m_readTimer.cancel();
    m_activityTimer.restart();

    if(error == asio::error::operation_aborted)
        return;

    if(m_connected) {
        if(!error) {
            if(m_recvCallback) {
                const char* header = boost::asio::buffer_cast<const char*>(m_inputStream.data());
                m_recvCallback((uint8*)header, recvSize);
            }
        } else
            handleError(error);
    }

    if(!error)
        m_inputStream.consume(recvSize);
}

void Connection::onTimeout(const boost::system::error_code& error)
{
    if(error == asio::error::operation_aborted)
        return;

    handleError(asio::error::timed_out);
}

void Connection::handleError(const boost::system::error_code& error)
{
    if(error == asio::error::operation_aborted)
        return;

    m_error = error;
    if(m_errorCallback)
        m_errorCallback(error);
    if(m_connected || m_connecting)
        close();
}

int Connection::getIp()
{
    boost::system::error_code error;
    const boost::asio::ip::tcp::endpoint ip = m_socket.remote_endpoint(error);
    if(!error)
        return boost::asio::detail::socket_ops::host_to_network_long(ip.address().to_v4().to_ulong());

    g_logger.error("Getting remote ip");
    return 0;
}
