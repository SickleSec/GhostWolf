![GhostWolf Logo](logo.png)
# 幽狼

GhostWolf 是一个强大的内存数据提取工具，专门设计用于从浏览器和远程控制软件中提取敏感信息。本项目基于 [CookieKatz](https://github.com/Meckazin/ChromeKatz) 项目开发，在其基础上扩展了更多功能。


## 主要功能

- **浏览器 Cookie 提取**
  - 支持 Chrome、Edge、Firefox 最新版本
  - 支持隐私模式下的 Cookie 提取
  - 直接从内存中读取数据，无需文件系统访问

- **浏览器密码提取**
  - 支持 Edge最新版本账户密码获取

- **ToDesk 信息提取**
  - 支持读取 ToDesk 账户密码
  - 支持获取设备列表
  - 支持读取已保存的远程连接密码

## 测试系统

- Windows 11
- 最新版本的 Chrome、Edge、Firefox 浏览器
- 最新版本的 ToDesk 

## 注意事项

- 本工具仅供安全研究和授权测试使用
- 使用本工具时请确保遵守相关法律法规
- 请勿将本工具用于非法用途

## 免责声明

本工具仅供安全研究和授权测试使用。使用本工具进行任何未经授权的测试或攻击行为，均由使用者自行承担法律责任。

## 使用方式

### 基本用法
```
.\GhostWolf.exe
```

### 命令行参数
```
浏览器相关：
    /edge       获取Edge浏览器的Cookie
	      /pass   获取Edge浏览器保存的所有密码
    /chrome     获取Chrome浏览器的Cookie
    /firefox    获取Firefox浏览器的Cookie

ToDesk相关：
    /todesk     获取ToDesk凭据信息
        /list   列出所有设备
        /pass   列出所有设备密码

其他：
    /help       显示帮助信息（-h 同样可用）
```
