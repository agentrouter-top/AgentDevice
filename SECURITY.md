# 安全说明 / Security

## 报告漏洞

请不要在公开 issue 里报告漏洞。用 GitHub 的私密漏洞报告（本仓库 Security → Report a vulnerability）。我们会在 3 个工作日内回复。

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab), not in public issues.

## 设计要点

客户端 `agentdevice`（[client/README.md](client/README.md)；为什么自己做 SSH 服务：[ADR 0002](docs/adr/0002-own-ssh-server.md)）。

- **只在自己的私有网络里可达**：客户端内嵌 NetBird（用户态网络，不要管理员权限、不装驱动），加入本人自己的 NetBird 网络；SSH 只在 NetBird 的虚拟地址上监听，电脑自己的网络上不开任何端口。
- **每次连接都要短时证书**：SSH 登录用 AgentCompute 的 SSH 用户 CA 签发的 OpenSSH 用户证书（有效 10 分钟）：签发者必须是本机信任的 CA 公钥之一，只有一个 principal 且等于本机的 computer id，在有效期内，不带任何 critical option，`own@` 等于这台设备的主人（知道租户时 `ten@` 也要相同）。CA 公钥来自注册应答或沙箱的加入文件，每次启动再向 `GET /v1/ssh-user-ca` 取一次；遇到不认识的签发者再取一次（最多每分钟一次），所以 CA 轮换不用重启。AgentCompute 的 SSH 网关先查一遍，设备作为最后一跳再查一遍。原来的令牌密码（`aud: netbird`）只保留到 AgentHost 改用证书（AgentHost#385），之后删除（#253）。
- **只执行**：没有 MCP，没有自己的文件、命令或屏幕工具；SSH 会话以运行客户端的账户身份在整台电脑上执行（R58），不切换用户、不提权。端口转发只到本机回环地址，不做远程转发和代理转发。
- **命令文字不进命令行**：写进只有本人能打开的文件，由固定的明文运行器读完即删（工作区规则 R21）；整棵进程树放进 Job Object（Windows）或进程组，断开时一起结束。
- **一个可见窗口**：Windows 上常驻一个「AgentRouter 设备」窗口，每件 Agent 做的事一行；关掉窗口就断开。
- **登录和移除**：设备码登录本人账号；在「我的设备」里移除后，客户端关掉 SSH 会话、结束登录并忘掉注册。
- **不签名**：现阶段的构建没有代码签名，见 [docs/adr/0001-code-signing.md](docs/adr/0001-code-signing.md)；降低误报的构建要求见 [docs/development/AV-HYGIENE.md](docs/development/AV-HYGIENE.md)（CI 检查）。

## Design summary

The client joins its owner's private, self-hosted NetBird network in userspace (no administrator rights, no driver)
and serves SSH only on its NetBird address: no port on the computer's own network. Every SSH session authenticates
with a 10-minute OpenSSH user certificate of AgentCompute's SSH user CA (signer one of the trusted CA keys, one
principal = this computer's id, valid now, no critical option, `own@` = the device's owner), checked by AgentCompute's
SSH gateway and again on the device; the CA keys come with the enrolment or the join file and are read again at each
start (`GET /v1/ssh-user-ca`) and on an unknown signer. The former token password (`aud: netbird`) stays only until
AgentHost moved to certificates (AgentHost#385). The device only executes:
no MCP, no tools of its own; a session runs as the client's account on the whole computer (R58); forwarding reaches
loopback only. Command text travels through owner-only files read by a fixed runner (R21); process trees end with the
session. Builds are currently unsigned (ADR 0001).
