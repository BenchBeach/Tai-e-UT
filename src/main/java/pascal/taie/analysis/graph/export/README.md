# Graph Exporter

导出指定方法的控制流图（CFG）和数据流图（DFG）到 JSON 格式。

## 功能特性

- **CFG（控制流图）**: 包含方法的所有语句节点和控制流边
- **DFG（数据流图）**: 基于 def-use 链的数据依赖关系图

## 使用方法

### 基本命令格式

```bash
java -jar tai-e-all.jar \
  -cp <class-path> \
  --input-classes <class-name> \
  -java <java-version> \
  -a 'graph-export=method:"<方法签名>";output:"<输出路径>"'
```

### 参数说明

| 参数 | 说明 | 是否必需 |
|------|------|----------|
| `method` | 要分析的方法签名 | ✅ 是 |
| `output` | JSON 输出文件路径 | ❌ 否（默认: `output/graphs/{ClassName}_{methodName}.json`）|

### 方法签名格式

```
<类全名: 返回类型 方法名(参数类型1,参数类型2,...)>
```

**注意**: 由于签名中包含冒号，需要用双引号包裹 `method` 参数值。

## 示例

### 示例 1: 使用默认输出路径

```bash
java -jar build/tai-e-all-0.5.2-SNAPSHOT.jar \
  -cp /path/to/project/target/classes \
  --input-classes com.example.MyClass \
  -java 8 \
  -a 'graph-export=method:"<com.example.MyClass: void myMethod(int,java.lang.String)>"'
```

输出文件将保存到: `output/graphs/MyClass_myMethod.json`

### 示例 2: 指定输出路径

```bash
java -jar build/tai-e-all-0.5.2-SNAPSHOT.jar \
  -cp /path/to/project/target/classes \
  --input-classes com.example.MyClass \
  -java 8 \
  -a 'graph-export=method:"<com.example.MyClass: int calculate(double)>";output:"/tmp/my_graph.json"'
```

输出文件将保存到: `/tmp/my_graph.json`

### 示例 3: 分析 Apache Commons Math 的方法

```bash
java -jar build/tai-e-all-0.5.2-SNAPSHOT.jar \
  -cp /path/to/commons-math/commons-math-core/target/classes \
  --input-classes org.apache.commons.math4.core.jdkmath.AccurateMath \
  -java 8 \
  -a 'graph-export=method:"<org.apache.commons.math4.core.jdkmath.AccurateMath: double pow(double,long)>";output:"/tmp/pow_graph.json"'
```

## JSON 输出格式

```json
{
  "method": "<方法签名>",
  "cfg": {
    "nodes": [...],
    "edges": [...]
  },
  "dfg": {
    "nodes": [...],
    "edges": [...]
  }
}
```

### CFG 节点结构

```json
{
  "id": "stmt_0",
  "index": 0,
  "type": "Invoke",
  "label": "语句内容",
  "lineNumber": 10,
  "def": "定义的变量",
  "uses": ["使用的变量列表"]
}
```

特殊节点:
- `entry`: 方法入口节点
- `exit`: 方法出口节点

### CFG 边类型

| 类型 | 说明 |
|------|------|
| `ENTRY` | 从入口到第一条语句 |
| `FALL_THROUGH` | 顺序执行 |
| `GOTO` | goto 跳转 |
| `IF_TRUE` | if 条件为真 |
| `IF_FALSE` | if 条件为假 |
| `SWITCH_CASE` | switch case 分支 |
| `SWITCH_DEFAULT` | switch default 分支 |
| `RETURN` | 返回到出口 |
| `CAUGHT_EXCEPTION` | 异常捕获 |

### DFG 节点结构

```json
{
  "id": "stmt_0",
  "index": 0,
  "type": "Copy",
  "label": "x = 1",
  "lineNumber": 10,
  "def": "x",
  "defVar": "x",
  "uses": ["1"],
  "useVars": []
}
```

### DFG 边结构

```json
{
  "source": "stmt_0",
  "target": "stmt_3",
  "variable": "x",
  "type": "DEF_USE"
}
```

DFG 边表示**数据依赖关系**（def-use chains）：
- `source`: 定义变量的语句
- `target`: 使用该变量的语句
- `variable`: 涉及的变量名
- `type`: 边类型（目前只有 `DEF_USE`）

## 依赖的分析

`graph-export` 分析依赖于以下分析:
- `cfg`: 控制流图构建
- `reach-def`: 到达定义分析

这些依赖会自动运行，无需手动指定。

## 注意事项

1. 确保目标方法不是 `abstract` 或 `native` 方法
2. 需要提供正确的 classpath，包含目标类的 `.class` 文件
3. 如果输出路径的父目录不存在，会自动创建
4. 建议使用 `-java 8` 参数指定 Java 版本，以正确加载 JRE 类库

