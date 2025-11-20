`dev-run.sh` 脚本是 CRS-java 系统的本地测试和开发入口脚本。

## 脚本概述

这是一个用于在开发环境中运行 CRS-java 的 Bash 脚本，负责设置环境、配置项目并启动漏洞检测流程。

## 主要功能模块详解

### 1. **目标项目选择函数** `pick_target_cp()`

```bash
pick_target_cp() {
  # 查找所有可用的目标项目
  dirs=()
  while IFS= read -r -d $'\0'; do
    dirs+=("$REPLY")
  done < <(find /cp_root/projects/aixcc/jvm -mindepth 1 -maxdepth 1 -type d -print0 | \
           sed 's|/cp_root/projects/aixcc/jvm/||g')

  # 交互式选择目标
  echo "CRS_TARGET is not set, select one from the following (only aixcc/jvm/xxx are presented):"
  select dir in "${dirs[@]}"; do
    if [[ -n "$dir" ]]; then
      export CRS_TARGET=aixcc/jvm/`basename "$dir"`
      echo "You have selected: $CRS_TARGET"
      break
    else
      echo "Invalid selection. Please try again."
    fi
  done
}
```

**作用**：当用户没有指定目标时，提供交互式选择界面。

### 2. **目标确定函数** `determine_CRS_TARGET()`

```bash
determine_CRS_TARGET() {
  if [[ -z "$CRS_TARGET" ]]; then
    if [[ -t 0 ]]; then
      # 交互式shell：让用户选择目标
      pick_target_cp
    else
      # 非交互式shell：直接退出
      echo "CRS_TARGET is not set. Exiting."
      exit 1
    fi
  fi
}
```

**作用**：根据运行环境决定如何处理未设置的目标。

### 3. **项目目录设置函数**

#### `setup_src_proj()` - 设置项目源码
```bash
setup_src_proj() {
    src_proj=/src-`basename $CRS_TARGET`/oss-fuzz/projects/$CRS_TARGET
    rm -rf $src_proj
    mkdir -p $src_proj
    rsync -a --exclude=".aixcc" /cp_root/projects/$CRS_TARGET/ $src_proj
    # 处理差异模式
    if [[ -z "$DIFF_MODE" ]]; then
      if [[ -f "/cp_root/projects/$CRS_TARGET/.aixcc/ref.diff" ]]; then
        echo "Diff mode enabled"
        rsync -a "/cp_root/projects/$CRS_TARGET/.aixcc/ref.diff" $src_proj/ref.diff
      fi
    fi
}
```

#### `setup_src_repo()` - 设置代码仓库
```bash
setup_src_repo() {
    src_repo=/src-`basename $CRS_TARGET`/repo
    rm -rf $src_repo
    mkdir -p $src_repo
    rsync -a /cp_root/build/repos/$CRS_TARGET/ $src_repo
}
```

#### `setup_out()` - 设置输出目录
```bash
setup_out() {
    out_dir=/out-`basename $CRS_TARGET`
    rm -rf $out_dir
    mkdir -p $out_dir
    rsync -a /cp_root/build/out/$CRS_TARGET/ $out_dir
    # 清理旧的jazzer文件，保留驱动存根
    find $out_dir -type f | while read f; do
      basename=$(basename "$f")
      if [[ "$basename" =~ ^jazzer.*$ ]]; then
        if [[ "$basename" != "jazzer_driver_with_sanitizer" ]]; then
          rm -f "$f"
        fi
      fi
    done
    rsync -a $JAVA_CRS_SRC/jazzer_driver_stub $out_dir/jazzer_driver
}
```

### 4. **环境变量设置函数**

#### `setup_rest_env()` - 设置运行环境
```bash
setup_rest_env() {
  export FUZZING_ENGINE=libfuzzer
  export SANITIZER=${SANITIZER:-address}  # 默认为地址消毒器
  export HELPER=True
  export RUN_FUZZER_MODE=interactive
  export SRC="/src-`basename $CRS_TARGET`"
  export OUT="/out-`basename $CRS_TARGET`"
  export SEED_SHARE_DIR="/seed-shared-`basename $CRS_TARGET`"
  export SARIF_SHARE_DIR="/sarif-shared-`basename $CRS_TARGET`"
  export SARIF_ANA_RESULT_DIR="/sarif-ana-result-`basename $CRS_TARGET`"
  export SARIF_REACHABILIY_SHARE_DIR="/sarif-reachability-shared-`basename $CRS_TARGET`"
  export CRS_JAVA_SHARE_DIR="/crs-java-shared-`basename $CRS_TARGET`"
  export CRS_JAVA_TEST_ENV_ROLE="leader"
  export TARBALL_FS_DIR="/tarball-fs"
  unset JAVA_CRS_IN_COMPETITION  # 标记为非竞赛模式
}
```

### 5. **测试配置更新函数** `update_crs_test_cfg()`

```bash
update_crs_test_cfg() {
  # 生成测试配置
  if ! python3.12 -u ./tests/gen_test_cfg.py; then
    echo ERROR: Failed to gen crs test config
    exit 1
  fi
  # 合并配置
  if ! python3.12 -u javacrscfg.py merge-crs-cfg ./crs-java.config /tmp/test.config; then
    echo ERROR: Failed to update crs test config
    exit 1
  fi
}
```

### 6. **核心运行函数** `run_crs()`

```bash
run_crs() {
  pushd "${JAVA_CRS_SRC}" > /dev/null

  DEFAULT_CFG="${JAVA_CRS_SRC}/crs-java.config"
  : "${JAVACRS_CFG:=${1:-${DEFAULT_CFG}}}"
  setup_rest_env

  if [[ -z "$CRS_JAVA_TEST" ]]; then
    # 正常运行模式
    echo ">> CRS NORMAL RUN <<"
    python3.12 -u ./main.py "${JAVACRS_CFG}" 2>&1 | tee ./crs-java.log
  else
    # 测试运行模式
    echo ">> CRS TEST RUN <<"
    update_crs_test_cfg
    if ! python3.12 -u ./main.py "${JAVACRS_CFG}" 2>&1 | tee ./crs-java.log; then
      echo ERROR: crs-java run failed with ret $?
      exit 1
    fi
    # 运行端到端测试检查
    python3.12 -u ./tests/e2e_result_checker.py | tee ./e2e-check.log
    rc=$?
    # 复制日志文件
    cp ./crs-java.log /crs-workdir/worker-0/
    cp ./e2e-check.log /crs-workdir/worker-0/
    mv /crs-workdir/worker-0 /crs-workdir/`basename $CRS_TARGET`
    # 处理测试结果
    if [ $rc -eq 0 ]; then
      echo ERROR: e2e result check failed
      if [[ -z "${CRS_JAVA_TEST_DEBUG}" ]]; then
        echo "E2E test debugging mode not enabled, exiting."
        exit 1
      else
        echo "E2E test debugging mode enabled, will NOT exit."
        sleep infinity
      fi
    fi
  fi

  popd > /dev/null
}
```

### 7. **系统设置函数** `setup_sys()`

```bash
setup_sys() {
  ulimit -c 0  # 禁用核心转储
  sysctl -w fs.file-max=2097152  # 增加文件描述符限制
  sysctl -w fs.inotify.max_user_instances=512  # 增加inotify实例限制
}
```

## 执行流程

1. **确定目标**：`determine_CRS_TARGET`
2. **设置目录**：`setup_cp_dirs`
3. **系统配置**：`setup_sys`
4. **运行CRS**：`run_crs "$1"`

## 关键环境变量

- `CRS_TARGET`：目标项目名称（必需）
- `CRS_JAVA_TEST`：测试模式标志
- `CRS_JAVA_TEST_DEBUG`：测试调试模式
- `JAVA_CRS_SRC`：CRS源码目录
- `DIFF_MODE`：差异分析模式

## 使用场景

### 正常开发运行
```bash
CRS_TARGET=aixcc/jvm/mock-java ./dev-run.sh
```

### 测试模式运行
```bash
CRS_JAVA_TEST=1 CRS_TARGET=aixcc/jvm/mock-java ./dev-run.sh
```

### 交互式选择目标
```bash
./dev-run.sh  # 会弹出选择界面
```

这个脚本是整个 CRS-java 系统在开发环境中的核心入口点，负责协调所有组件的初始化和执行。