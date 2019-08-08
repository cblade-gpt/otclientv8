-- private variables
local topMenu
local leftButtonsPanel
local rightButtonsPanel
local leftGameButtonsPanel
local rightGameButtonsPanel
local fpsUpdateEvent = nil

local HIDE_TOPMENU = false

-- private functions
local function addButton(id, description, icon, callback, panel, toggle, front)
  local class
  if toggle then
    class = 'TopToggleButton'
  else
    class = 'TopButton'
  end

  local button = panel:getChildById(id)
  if not button then
    button = g_ui.createWidget(class)
    if front then
      panel:insertChild(1, button)
    else
      panel:addChild(button)
    end
  end
  button:setId(id)
  button:setTooltip(description)
  button:setIcon(resolvepath(icon, 3))
  button.onMouseRelease = function(widget, mousePos, mouseButton)
    if widget:containsPoint(mousePos) and mouseButton ~= MouseMidButton then
      callback()
      return true
    end
  end
  return button
end

-- public functions
function init()
  connect(g_game, { onGameStart = online,
                    onGameEnd = offline,
                    onPingBack = updatePing })

  topMenu = g_ui.displayUI('topmenu')

  leftButtonsPanel = topMenu:getChildById('leftButtonsPanel')
  rightButtonsPanel = topMenu:getChildById('rightButtonsPanel')
  leftGameButtonsPanel = topMenu:getChildById('leftGameButtonsPanel')
  rightGameButtonsPanel = topMenu:getChildById('rightGameButtonsPanel')
  pingLabel = topMenu:getChildById('pingLabel')
  fpsLabel = topMenu:getChildById('fpsLabel')
  
  g_keyboard.bindKeyDown('Ctrl+Shift+T', toggle)
  
  if g_game.isOnline() then
    online()
  end
  
  updateFps()
  
  if HIDE_TOPMENU then
    topMenu:setHeight(0) 
    topMenu:hide()
  end
end

function terminate()
  disconnect(g_game, { onGameStart = online,
                       onGameEnd = offline,
                       onPingBack = updatePing })
  removeEvent(fpsUpdateEvent)
  
  topMenu:destroy()
end

function online()
  showGameButtons()

  addEvent(function()
    if modules.client_options.getOption('showPing') and (g_game.getFeature(GameClientPing) or g_game.getFeature(GameExtendedClientPing)) then
      pingLabel:show()
    else
      pingLabel:hide()      
    end
  end)
end

function offline()
  hideGameButtons()
  pingLabel:hide()
end

function updateFps()
  fpsUpdateEvent = scheduleEvent(updateFps, 500)
  text = 'FPS: ' .. g_app.getFps()
  fpsLabel:setText(text)
end

function updatePing(ping)
  local text = 'Ping: '
  local color
  if ping < 0 then
    text = text .. "??"
    color = 'yellow'
  else
    text = text .. ping .. ' ms'
    if ping >= 500 then
      color = 'red'
    elseif ping >= 250 then
      color = 'yellow'
    else
      color = 'green'
    end
  end
  pingLabel:setColor(color)
  pingLabel:setText(text)
end

function setPingVisible(enable)
  pingLabel:setVisible(enable)
end

function setFpsVisible(enable)
  fpsLabel:setVisible(enable)
end

function addLeftButton(id, description, icon, callback, front)
  return addButton(id, description, icon, callback, leftButtonsPanel, false, front)
end

function addLeftToggleButton(id, description, icon, callback, front)
  return addButton(id, description, icon, callback, leftButtonsPanel, true, front)
end

function addRightButton(id, description, icon, callback, front)
  return addButton(id, description, icon, callback, rightButtonsPanel, false, front)
end

function addRightToggleButton(id, description, icon, callback, front)
  return addButton(id, description, icon, callback, rightButtonsPanel, true, front)
end

function addLeftGameButton(id, description, icon, callback, front)
  return addButton(id, description, icon, callback, leftGameButtonsPanel, false, front)
end

function addLeftGameToggleButton(id, description, icon, callback, front)
  return addButton(id, description, icon, callback, leftGameButtonsPanel, true, front)
end

function addRightGameButton(id, description, icon, callback, front)
  return addButton(id, description, icon, callback, rightGameButtonsPanel, false, front)
end

function addRightGameToggleButton(id, description, icon, callback, front)
  return addButton(id, description, icon, callback, rightGameButtonsPanel, true, front)
end

function showGameButtons()
  leftGameButtonsPanel:show()
  rightGameButtonsPanel:show()
end

function hideGameButtons()
  leftGameButtonsPanel:hide()
  rightGameButtonsPanel:hide()
end

function getButton(id)
  return topMenu:recursiveGetChildById(id)
end

function getTopMenu()
  return topMenu
end

function toggle()
  local menu = getTopMenu()
  if not menu then
    return
  end

  if HIDE_TOPMENU then
    return
  end

  if menu:isVisible() then
    menu:hide()
    modules.client_background.getBackground():addAnchor(AnchorTop, 'parent', AnchorTop)
    modules.game_interface.getRootPanel():addAnchor(AnchorTop, 'parent', AnchorTop)
  else
    menu:show()
    topMenu:setHeight(36) 
    modules.client_background.getBackground():addAnchor(AnchorTop, 'topMenu', AnchorBottom)
    modules.game_interface.getRootPanel():addAnchor(AnchorTop, 'topMenu', AnchorBottom)
  end
end