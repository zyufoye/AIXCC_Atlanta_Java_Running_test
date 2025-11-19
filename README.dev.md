# 本地运行CRS_Java 

在本地构建、运行和开发 CRS-java 的详细信息。

CRS 是“引擎”，CP 是“被测试/被分析的目标”，dev.sh 是统一运维脚本。

```bash
# build CP(s) 首先，构建CP镜像
./dev.sh build-cp '<target-list>' '<cp-name-regex>'
# e.g., ./dev.sh build-cp cps "aixcc/jvm/*"

# build CRS image 
# 构建 CRS 镜像 构建 CRS 这一“核心服务”的 Docker 镜像（而不是具体的 CP）
# 更新了 CRS 源码（比如 ./crs 目录里的代码）后，需要重新构建镜像
./dev.sh build-crs

# run CRS on target CP according to `crs/crs-java.config`
# 选择具体 CP 运行 CRS
# LITELLM_KEY 是给 CRS 使用的大模型/推理服务的 API Key
# CRS_TARGET 是本次运行的目标 CP
LITELLM_KEY=xxx CRS_TARGET=aixcc/jvm/fuzzy ./dev.sh run

# 上述流程组合：用 CRS 镜像 + 指定的 CP 镜像，按照 crs/crs-java.config 的配置，启动一套运行环境，执行对 aixcc/jvm/fuzzy 的分析/测试/运行流程

# clean 清理
./dev.sh clean

# DEV mode, (host `./crs` mount to container)
# DEV 模式（挂载本地源码，方便开发）
# 把本机的 ./crs 目录 mount 到容器，改本地文件，容器内实时生效 

DEV=1 LITELLM_KEY=xxx ./dev.sh custom sleep infinity
# Get a shell, docker exec -it ...
## inside container
## - specify a target
CRS_TARGET=aixcc/jvm/fuzzy ./dev-run.sh ...
## - interactively pick a target
./dev-run.sh ...
## - or do anything u want

# install yq dependency
./dev.sh install-yq

# update CRS config documentation
# pip3 install jsonschema-markdown
./dev.sh gen-doc

# run crs e2e functionality test
LITELLM_KEY=xxx ./dev.sh test aixcc/jvm/mock-java OssFuzz1 [CRS_TTL_TIME] [true]
```

关键在于 dev.sh 脚本，它提供了统一的运维接口，包括构建、运行、清理等操作。

