# KEYPROV-LIFECYCLE-1 共享生命周期向量

状态：规范 golden + 可执行参考模型，不是生产组件 conformance / mock 集成 / 真车验收报告。

- lifecycle-vectors.json：24个场景组，包含边界和故障子例；input/expected显式固定；T0固定，不依赖真实时间。
- oracle.py：仅验证本规范的决策与固定期望自洽。运行 python oracle.py。
- reference-report.json：参考模型运行结果，禁止包装成VMD/TSP/SEC实际CI全绿。
- SHA256SUMS：整文件hash，双方仓库本地固定同版本fixtures；不要以expected_hash包含自身的递归方式计算集合hash。

接入要求：各仓库adapter将input映射到真实决策函数/时钟/存储故障注入，输出actual和实际副作用计数，不调用本oracle生成actual。生产CI逐项比对expected、输入hash和expected_hash，生成JUnit及相同schema报告；release-set要求同一vectors文件SHA256、profile和参数。VEH-PROTO只同步文档和hash，不发布代码artifact，车端不运行时访问PAR仓库。

本集只新增生命周期语义，不伪造有效密文、KCV、proof。必须叠加既有PAR-009/FW-020/SEC-022原始bytes/签名向量，再跑实际codec与SEC provider。本参考模型覆盖纯函数，实际调度退避、文件原子迁移、DB锁竞争、字节patch、MQTT传输、IPC与HSM必须按CR集成计划验证。

缺口门禁：实际Java/C++ adapters、双方CI接入、mock-VMD↔真实coordinator、真实SEC/Provider、VAGW/MQTT与真车全部尚未执行，不能签Definition of Done。
