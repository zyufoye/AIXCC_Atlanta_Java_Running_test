#!/usr/bin/env python3
import copy
import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from uuid import UUID

import aiofiles
from pydantic import BaseModel


class File(BaseModel):
    name: str
    path: Path

    class Config:
        frozen = True

    @classmethod
    def frm_dict(cls, data) -> "File":
        return cls(name=data["name"], path=Path(data["path"]))

    def to_dict(self):
        return {"name": self.name, "path": str(self.path)}


class Function(BaseModel):
    func_name: str
    file_name: str | None  # absolute path
    class_name: str | None = None
    func_sig: str | None = None
    method_desc: str | None = None
    start_line: int | None = None
    end_line: int | None = None

    class Config:
        frozen = True

    @classmethod
    def frm_dict(cls, data) -> "Function":
        return cls(**data)

    def to_dict(self):
        return {
            "func_name": self.func_name,
            "file_name": self.file_name,
            "class_name": self.class_name,
            "func_sig": self.func_sig,
            "method_desc": self.method_desc,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


class CodeLocation(BaseModel):
    file: File
    function: Function | None = None
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None

    class Config:
        frozen = True

    @classmethod
    def frm_dict(cls, data) -> "CodeLocation":
        file = File.frm_dict(data["file"])
        function = Function.frm_dict(data["function"]) if data.get("function") else None
        return cls(
            file=file,
            function=function,
            start_line=data.get("start_line"),
            end_line=data.get("end_line"),
            start_column=data.get("start_column"),
            end_column=data.get("end_column"),
        )

    def to_dict(self):
        return {
            "file": self.file.to_dict(),
            "function": self.function.to_dict() if self.function else None,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "end_column": self.end_column,
        }


class ConfidenceLevel(Enum):
    HIGH = "high"
    LOW = "low"


class SarifReachabilityResult(BaseModel):
    code_location: CodeLocation
    confidence_level: ConfidenceLevel
    callgraph: dict  # jsonable python dict of CallGraph. See sarif.validator.reachability.callgraph.CallGraph.to_json()


class SarifAnalysisResult(BaseModel):
    sarif_id: UUID
    rule_id: str
    reachable_harness: str
    reachability_results: list[SarifReachabilityResult]


class CRSJAVASarifReport:
    sarif_id: UUID
    rule_id: str
    reachable_harnesses: Set[str]
    code_locations: Set[CodeLocation]
    solved: bool

    def __init__(
        self,
        sarif_id: UUID,
        rule_id: str,
        reachable_harnesses: Set[str],
        code_locations: Set[CodeLocation],
        solved: bool,
    ):
        self.sarif_id = sarif_id
        self.rule_id = rule_id
        self.reachable_harnesses = reachable_harnesses
        self.code_locations = code_locations
        self.solved = solved

    def add_result(self, result: SarifAnalysisResult) -> bool:
        """Add a result to the report."""
        updated = False
        assert result.sarif_id == self.sarif_id
        assert result.rule_id == self.rule_id
        if result.reachable_harness not in self.reachable_harnesses:
            self.reachable_harnesses.add(result.reachable_harness)
            updated = True
        for r in result.reachability_results:
            if r.code_location not in self.code_locations:
                self.code_locations.add(r.code_location)
                updated = True
        return updated

    def merge(self, other: "CRSJAVASarifReport") -> bool:
        """Merge another CRSJAVASarifReport into this one."""
        if self.sarif_id != other.sarif_id or self.rule_id != other.rule_id:
            return False
        updated = False
        for h in other.reachable_harnesses:
            if h not in self.reachable_harnesses:
                self.reachable_harnesses.add(h)
                updated = True
        for loc in other.code_locations:
            if loc not in self.code_locations:
                self.code_locations.add(loc)
                updated = True
        if other.solved and not self.solved:
            self.solved = True
            updated = True
        return updated

    def is_solved(self) -> bool:
        """Check if the report is solved."""
        return self.solved

    def mark_as_solved(self):
        """Mark the report as solved."""
        self.solved = True

    @classmethod
    def frm_results(
        cls, results: List[SarifAnalysisResult], solved: bool
    ) -> "CRSJAVASarifReport":
        if len(results) == 0:
            raise ValueError("Cannot create CRSJAVASarifReport from empty results")
        # check sarif_id and rule_id consistency
        for result in results:
            if (
                result.sarif_id != results[0].sarif_id
                or result.rule_id != results[0].rule_id
            ):
                raise ValueError("All results must have the same sarif_id and rule_id")
        obj = cls(
            sarif_id=results[0].sarif_id,
            rule_id=results[0].rule_id,
            reachable_harnesses=set(),
            code_locations=set(),
            solved=solved,
        )
        for result in results:
            obj.add_result(result)
        return obj

    @classmethod
    def frm_dict(cls, data) -> "CRSJAVASarifReport":
        sarif_id = UUID(data["sarif_id"])
        rule_id = data["rule_id"]
        reachable_harnesses = set(data.get("reachable_harnesses", []))
        code_locations = {
            CodeLocation.frm_dict(cl) for cl in data.get("code_locations", [])
        }
        solved = data["solved"]
        return cls(
            sarif_id=sarif_id,
            rule_id=rule_id,
            reachable_harnesses=reachable_harnesses,
            code_locations=code_locations,
            solved=solved,
        )

    def to_dict(self):
        sorted_harnesses = list(self.reachable_harnesses)
        sorted_harnesses.sort()
        sorted_locs = list(self.code_locations)
        sorted_locs.sort(
            key=lambda loc: (
                loc.file.name,
                loc.function.func_name,
                loc.start_line,
                loc.end_line,
                loc.start_column,
                loc.end_column,
            )
        )
        return {
            "sarif_id": str(self.sarif_id),
            "rule_id": self.rule_id,
            "reachable_harnesses": sorted_harnesses,
            "code_locations": [cl.to_dict() for cl in sorted_locs],
            "solved": self.solved,
        }


class InsnCoordinate:
    """Unique coorindate of an insn in bytecode."""

    def __init__(
        self,
        class_name: str,
        method_name: str,
        method_desc: str,
        bytecode_offset: int,
        mark_desc: str,
        file_name: str,
        line_num: int,
    ):
        self.class_name = class_name
        self.method_name = method_name
        self.method_desc = method_desc
        self.bytecode_offset = bytecode_offset
        self.mark_desc = mark_desc
        self.file_name = file_name
        self.line_num = line_num

        self.has_src_info = self.mark_desc and self.class_name and self.line_num != -1
        self.has_bytecode_info = (
            self.mark_desc
            and self.class_name
            and self.method_name
            and self.method_desc
            and self.bytecode_offset != -1
        )
        if not self.has_src_info and not self.has_bytecode_info:
            raise ValueError(
                f"Incomplete info in InsnCoordinate: src_info {self.has_src_info}, bytecode_info {self.has_bytecode_info}, {self.__dict__}"
            )
        if self.class_name is not None:
            self.class_name = self.class_name.replace("/", ".")

    @classmethod
    def frm_dict(cls, coord_dict: Dict[str, Any]) -> "InsnCoordinate":
        return cls(
            class_name=coord_dict.get("class_name", None),
            method_name=coord_dict.get("method_name", None),
            method_desc=coord_dict.get("method_desc", None),
            bytecode_offset=int(coord_dict.get("bytecode_offset") or -1),
            mark_desc=coord_dict.get("mark_desc", None),
            file_name=coord_dict.get("file_name", None),
            line_num=int(coord_dict.get("line_num") or -1),
        )

    def to_conf(self) -> str | None:
        """Convert the InsnCoordinate to a conf."""
        if self.has_bytecode_info:
            return "#".join(
                [
                    "caller",
                    self.class_name,
                    self.method_name,
                    self.method_desc if self.method_desc else "",
                    self.file_name if self.file_name else "",
                    str(self.line_num),
                    str(self.bytecode_offset),
                    self.mark_desc if self.mark_desc else "",
                ]
            )
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "class_name": self.class_name,
            "method_name": self.method_name,
            "method_desc": self.method_desc,
            "bytecode_offset": self.bytecode_offset,
            "mark_desc": self.mark_desc,
            "file_name": self.file_name,
            "line_num": self.line_num,
        }

    def _is_in_stack_frame(self, frame: str) -> bool:
        return (f"{self.class_name}.{self.method_name}") in frame and (
            f"({self.file_name}:{self.line_num})"
        ) in frame

    def is_in_stack_frames(self, frames: list[str]) -> bool:
        for frame in frames:
            if self._is_in_stack_frame(frame):
                return True
        return False

    def redis_key(self) -> str:
        """Get a Redis key for the InsnCoordinate."""
        return f"coord#{self.class_name}#{self.method_name}#{self.method_desc}#{self.bytecode_offset}#{self.file_name}#{self.line_num}#{self.mark_desc}"

    def id(self) -> str:
        """Get a unique ID for the InsnCoordinate."""
        return f"{self.class_name}.{self.method_name}.{self.method_desc}.{self.bytecode_offset}.{self.file_name}.{self.line_num}.{self.mark_desc}"

    def __hash__(self):
        return hash(self.id())

    def __eq__(self, other: Any):
        if not isinstance(other, InsnCoordinate):
            return False
        return self.id() == other.id()

    def __str__(self):
        return f"coord @ <{self.class_name} {self.method_name} {self.method_desc} {self.bytecode_offset} {self.file_name} {self.line_num} {self.mark_desc}>"

    def __repr__(self):
        return (
            f"InsnCoordinate(class_name='{self.class_name}', "
            f"method_name='{self.method_name}', "
            f"method_desc='{self.method_desc}', "
            f"bytecode_offset={self.bytecode_offset}, "
            f"mark_desc='{self.mark_desc}', "
            f"file_name='{self.file_name}', "
            f"line_num={self.line_num})"
        )


class BeepSeed:
    """beepseed is an input reaching a marked code point."""

    def __init__(
        self,
        target_cp: str,
        target_harness: str,
        data_sha1: str,
        data_hex_str: str | None,
        data_len: int,
        coord: InsnCoordinate,
        stack_hash: str,
        stack_trace: list | None,
        json_obj: Dict[str, Any],
    ):
        self.target_cp = target_cp
        self.target_harness = target_harness
        self.data_sha1 = data_sha1
        self.data_hex_str = data_hex_str
        self.data_len = data_len
        self.coord = coord
        # NOTE: stack_hash is about beepseed exec stacks
        self.stack_hash = stack_hash
        self.stack_trace = stack_trace
        self.json_obj = json_obj

    @classmethod
    def frm_dict(cls, dict_obj: Dict[str, Any]) -> "BeepSeed":
        """Create a BeepSeed object from a dictionary."""
        return cls(
            target_cp=dict_obj["target_cp"],
            target_harness=dict_obj["target_harness"],
            data_sha1=dict_obj["data_sha1"],
            data_hex_str=dict_obj.get("data", None),
            data_len=dict_obj["data_len"],
            coord=InsnCoordinate.frm_dict(dict_obj["coordinate"]),
            stack_hash=dict_obj["stack_hash"],
            stack_trace=dict_obj.get("stack_trace", None),
            json_obj=dict_obj,
        )

    @classmethod
    async def frm_beep_file(cls, json_path: Path) -> "BeepSeed":
        """Create a BeepSeed object from a JSON file path."""
        async with aiofiles.open(json_path, mode="r") as f:
            json_obj = json.loads(await f.read())

        json_obj["data_len"] = len(json_obj["data"]) // 2 if "data" in json_obj else 0
        return cls.frm_dict(json_obj)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the BeepSeed object to a JSON-serializable dictionary."""
        return {
            "target_cp": self.target_cp,
            "target_harness": self.target_harness,
            "data_sha1": self.data_sha1,
            "data": self.data_hex_str,
            "data_len": self.data_len,
            "coordinate": self.coord.to_dict(),
            "stack_hash": self.stack_hash,
            "stack_trace": self.stack_trace,
        }

    def is_empty_data(self) -> bool:
        return self.data_len == 0

    def filter_frames_from_codemarker(self, stack_frames=None):
        """Filter strategy: Remove frames starting from codemarker report function."""
        if stack_frames is None:
            stack_frames = self.stack_trace

        if not stack_frames:
            return []

        filtered_frames = []
        for frame in stack_frames[::-1]:
            frame_str = frame.get("frame_str", "")

            # 当找到代码标记器插桩帧时停止
            if (
                "com.code_intelligence.jazzer.api.Jazzer.reportCodeMarkerHit(Jazzer.java:229)"
                in frame_str
            ):
                break

            filtered_frames.append(frame_str)
        filtered_frames.reverse()
        return filtered_frames

    def get_bytes(self) -> bytes:
        """
        从十六进制字符串获取字节数据
        
        Returns:
            bytes: 输入数据的字节表示
        """
        if self.data_hex_str:
            return bytes.fromhex(self.data_hex_str)
        return b""

    def redis_key(self) -> str:
        """
        生成Redis缓存键
        
        Returns:
            str: 唯一的Redis键字符串
            
        格式：
            beep#{data_sha1}#{coord.redis_key()}
        """
        return f"beep#{self.data_sha1}#{self.coord.redis_key()}"

    def id(self) -> str:
        """
        生成唯一ID
        
        Returns:
            str: 唯一标识符字符串
        """
        return f"{self.coord.id()}.{self.data_sha1}"

    def __hash__(self):
        return hash(self.id())

    def __eq__(self, other):
        if not isinstance(other, BeepSeed):
            return False
        return self.id() == other.id()

    def __str__(self):
        return f"beep <{self.coord}, {self.stack_hash}, {self.data_sha1}, {self.data_len} bytes>"

    def __repr__(self):
        return (
            f"BeepSeed(target_cp='{self.target_cp}', "
            f"target_harness='{self.target_harness}', "
            f"data_sha1='{self.data_sha1}', "
            f"data_hex_str={self.data_hex_str}, "
            f"data_len={self.data_len}, "
            f"coord={self.coord}, "
            f"stack_hash='{self.stack_hash}', "
            f"stack_trace={self.stack_trace})"
        )


class Crash:
    """
    崩溃报告类
    
    表示在Java代码执行过程中发现的崩溃信息，包含崩溃位置、类型、消息等。
    是安全测试中发现实际漏洞的重要指标。
    
    属性：
        harness_name (str): 测试用例名称
        coord (InsnCoordinate): 崩溃位置的指令坐标
        sanitizer (str): 使用的 sanitizer 类型
        crash_msg (str): 崩溃消息
        frames (List[str]): 崩溃栈帧列表
        dedup_token (str): 去重令牌
        artifact_name (str): 崩溃产物名称
        artifact_path (str): 崩溃产物路径
        artifact_hexstr (str): 崩溃产物的十六进制表示
    
    用途：
        - 漏洞验证
        - 崩溃去重
        - 安全报告生成
        - 误报过滤
    """

    def __init__(
        self,
        harness_name: str,
        coord: InsnCoordinate,
        sanitizer: str,
        crash_msg: str,
        frames: List[str],
        dedup_token: str,
        artifact_name: str,
        artifact_path: str,
    ):
        """
        初始化崩溃报告
        
        Args:
            harness_name: 触发崩溃的测试用例名称
            coord: 崩溃位置的指令坐标
            sanitizer: 使用的安全检测器类型
            crash_msg: 崩溃消息内容
            frames: 崩溃栈帧列表
            dedup_token: 用于崩溃去重的令牌
            artifact_name: 崩溃产物文件名称
            artifact_path: 崩溃产物文件路径
        """
        self.harness_name = harness_name
        self.coord = coord
        self.sanitizer = sanitizer
        self.crash_msg = crash_msg
        self.frames = frames
        self.dedup_token = dedup_token
        self.artifact_name = artifact_name
        self.artifact_path = artifact_path
        self.artifact_hexstr = Path(artifact_path).read_bytes().hex()

    def __hash__(self):
        return hash(
            (
                self.harness_name,
                self.coord,
                self.sanitizer,
                self.dedup_token,
                self.artifact_hexstr,
            )
        )

    def __eq__(self, other):
        try:
            return (
                self.harness_name == other.harness_name
                and self.coord == other.coord
                and self.sanitizer == other.sanitizer
                and self.dedup_token == other.dedup_token
                and self.artifact_hexstr == other.artifact_hexstr
            )
        except AttributeError:
            return False


class Sinkpoint:
    """
    汇点类
    
    表示Java代码中可能存在安全漏洞的关键位置（汇点），是安全测试的核心概念。
    汇点综合了静态分析结果、动态执行信息、崩溃报告等多维度的安全信息。
    
    属性：
        coord (InsnCoordinate): 汇点的指令坐标
        type (Set[str]): 汇点类型集合
        in_diff (bool): 是否在差异分析范围内
        sarif_reports (Dict[UUID, CRSJAVASarifReport]): SARIF报告字典
        beepseeds (Set[BeepSeed]): 到达此汇点的种子集合
        crashes (Set[Any]): 相关的崩溃集合
        ana_reachability (Dict[str, bool]): 可访问性分析结果
        ana_exploitability (Dict[str, bool]): 可利用性分析结果
    
    用途：
        - 漏洞位置管理
        - 安全风险评估
        - 测试优先级排序
        - 漏洞利用验证
    """

    def __init__(
        self,
        coord: InsnCoordinate,
        type: Set[str],
        in_diff: bool,
        sarif_reports: Set[CRSJAVASarifReport] = None,
        beepseeds: Set[BeepSeed] = None,
        crashes: Set[Any] = None,
        ana_reachability: Dict[str, bool] = None,
        ana_exploitability: Dict[str, bool] = None,
    ):
        """
        初始化汇点
        
        Args:
            coord: 汇点的指令坐标
            type: 汇点类型集合
            in_diff: 是否在差异分析范围内
            sarif_reports: 相关的SARIF报告集合
            beepseeds: 到达此汇点的测试种子集合
            crashes: 相关的崩溃集合
            ana_reachability: 可访问性分析结果字典
            ana_exploitability: 可利用性分析结果字典
            
        数据验证：
            - 类型检查
            - 可访问性结果类型验证
            - 可利用性结果类型验证
        """
        self.coord = coord
        self.type: Set[str] = set(type)
        self.in_diff = in_diff
        self.sarif_reports: Dict[UUID, CRSJAVASarifReport] = {
            report.sarif_id: report for report in sarif_reports or {}
        }
        self.beepseeds: Set[BeepSeed] = set(beepseeds or set())
        self.crashes: Set[Any] = set(crashes or set())
        self.ana_reachability = dict(ana_reachability or dict())
        self.ana_exploitability = dict(ana_exploitability or dict())
        # 断言验证
        for t in self.type:
            assert isinstance(t, str), f"Invalid type in Sinkpoint: {t}"
        for k, v in self.ana_reachability.items():
            assert isinstance(k, str), f"Invalid type in Sinkpoint: {t}"
            assert isinstance(v, bool), f"Invalid type in Sinkpoint: {v}"
        for k, v in self.ana_exploitability.items():
            assert isinstance(k, str), f"Invalid type in Sinkpoint: {t}"
            assert isinstance(v, bool), f"Invalid type in Sinkpoint: {v}"

    def data_n_hash(self) -> Tuple[str, str]:
        """
        生成基于内容的哈希值用于跨进程比较
        
        Returns:
            Tuple[str, str]: (内容字符串, MD5哈希值)
            
        用途：
            - 跨进程数据同步
            - 缓存键生成
            - 数据一致性检查
        """
        content = json.dumps(self.to_dict(), sort_keys=True)
        return content, hashlib.md5(content.encode()).hexdigest()

    @classmethod
    def frm_dict(cls, sink_dict: Dict[str, Any]) -> "Sinkpoint":
        """
        从字典创建汇点对象
        
        Args:
            sink_dict: 包含汇点信息的字典
            
        Returns:
            Sinkpoint: 创建的汇点对象
            
        特殊处理：
            - 支持直接使用sink_dict作为coord_dict（用于llmpocgen和静态分析结果）
            - 自动添加mark_desc到类型集合
        """
        coord_dict = sink_dict.get("coord", {})
        if len(coord_dict) == 0:
            # 注意：如果没有提供coord键，尝试直接使用sink_dict
            # 这适用于llmpocgen和静态分析结果
            coord_dict = sink_dict
        sarif_reports = {
            CRSJAVASarifReport.frm_dict(report)
            for report in sink_dict.get("sarif_reports") or []
        }
        beepseeds = {
            BeepSeed.frm_dict(beepseed) for beepseed in sink_dict.get("beepseeds") or []
        }
        type = set(sink_dict.get("type") or set())
        mark_desc = coord_dict.get("mark_desc", None)
        if mark_desc:
            type.add(mark_desc)
        return cls(
            coord=InsnCoordinate.frm_dict(coord_dict),
            type=type,
            in_diff=sink_dict.get("in_diff", False),
            sarif_reports=sarif_reports,
            beepseeds=beepseeds,
            crashes=None,
            ana_reachability=sink_dict.get("ana_reachability", None),
            ana_exploitability=sink_dict.get("ana_exploitability", None),
        )

    @classmethod
    def frm_beepseed(cls, beepseed: BeepSeed) -> "Sinkpoint":
        """
        从BeepSeed创建汇点对象
        
        Args:
            beepseed: BeepSeed对象
            
        Returns:
            Sinkpoint: 基于BeepSeed创建的汇点对象
            
        用途：
            - 快速汇点创建
            - 动态执行结果转换
        """
        return cls(
            coord=beepseed.coord,
            type={beepseed.coord.mark_desc},
            in_diff=False,
            sarif_reports=set(),
            beepseeds={beepseed},
            crashes=set(),
            ana_reachability=None,
            ana_exploitability=None,
        )

    @classmethod
    def frm_crash(cls, crash: Crash) -> "Sinkpoint":
        """
        从Crash创建汇点对象
        
        Args:
            crash: Crash对象
            
        Returns:
            Sinkpoint: 基于Crash创建的汇点对象
            
        用途：
            - 崩溃结果转换
            - 漏洞验证
        """
        return cls(
            coord=crash.coord,
            type={crash.coord.mark_desc},
            in_diff=False,
            sarif_reports=set(),
            beepseeds=set(),
            crashes={crash},
            ana_reachability=None,
            ana_exploitability=None,
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        转换为JSON可序列化的字典
        
        Returns:
            dict: 包含汇点完整信息的字典，数据已排序
            
        特殊字段：
            reached: 是否被访问过
            exploited: 是否已被利用（产生崩溃）
        """
        sorted_types = list(self.type)
        sorted_types.sort()
        sorted_sarif_ids = list(self.sarif_reports.keys())
        sorted_sarif_ids.sort()
        sorted_beepseeds = list(self.beepseeds)
        sorted_beepseeds.sort(key=lambda b: b.data_sha1)
        return {
            "coord": self.coord.to_dict(),
            "type": sorted_types,
            "in_diff": self.in_diff,
            "sarif_reports": [
                self.sarif_reports[sarif_id].to_dict() for sarif_id in sorted_sarif_ids
            ],
            "beepseeds": [beepseed.to_dict() for beepseed in sorted_beepseeds],
            "ana_reachability": dict(self.ana_reachability),
            "ana_exploitability": dict(self.ana_exploitability),
            "reached": self.reached(),
            "exploited": self.exploited(),
        }

    def mark_as_sarif_target_if_should(
        self, logger, report: CRSJAVASarifReport
    ) -> bool:
        """
        检查并标记汇点作为SARIF目标
        
        Args:
            logger: 日志记录器
            report: SARIF报告
            
        Returns:
            bool: 是否成功标记为SARIF目标
            
        验证逻辑：
            - 检查代码位置的有效性
            - 验证类名匹配
            - 检查行号范围
        """
        marked_locs = (
            self.sarif_reports[report.sarif_id].code_locations
            if report.sarif_id in self.sarif_reports
            else set()
        )
        marked = False
        for loc in report.code_locations:
            if loc in marked_locs:
                marked = True
                break
            if (
                loc.function is None
                or loc.function.class_name is None
                or loc.start_line is None
            ):
                logger(
                    f"Invalid code location {loc.function} {loc.start_line} {loc.end_line} in SARIF result {report.sarif_id} {report.rule_id} {report.reachable_harnesses}, skipping"
                )
                continue
            if self.coord.line_num == -1:
                continue
            if loc.function.class_name != self.coord.class_name:
                # 注意：假设SARIF报告始终使用点分隔的类名
                continue
            # 同一类，现在检查是否在行号范围内
            start_line = loc.start_line
            end_line = loc.end_line if loc.end_line else loc.start_line
            if start_line <= self.coord.line_num <= end_line:
                marked = True
                break
        if marked:
            if report.sarif_id not in self.sarif_reports:
                self.sarif_reports[report.sarif_id] = report
            else:
                self.sarif_reports[report.sarif_id].merge(report)
            for h in report.reachable_harnesses:
                self.ana_reachability[h] = True
        return marked

    def merge(self, sp: "Sinkpoint") -> bool:
        """
        更新汇点信息
        
        Args:
            sp: 要合并的另一个汇点
            
        Returns:
            bool: 是否成功合并新信息
            
        合并策略：
            - 坐标必须相同才能合并
            - 合并类型集合
            - 更新差异分析标记
            - 合并SARIF报告
            - 添加新的测试种子和崩溃
            - 解决分析结果冲突
        """
        updated = False
        if self.coord != sp.coord:
            return updated
        for t in sp.type:
            if t not in self.type:
                self.type.add(t)
                updated = True
        if not self.in_diff and sp.in_diff:
            self.in_diff = True
            updated = True
        for sarif_id, report in sp.sarif_reports.items():
            if sarif_id not in self.sarif_reports:
                self.sarif_reports[sarif_id] = report
                updated = True
            else:
                updated |= self.sarif_reports[sarif_id].merge(report)
        for beepseed in sp.beepseeds:
            if beepseed not in self.beepseeds:
                self.beepseeds.add(beepseed)
                updated = True
        for crash in sp.crashes:
            if crash not in self.crashes:
                self.crashes.add(crash)
                updated = True
        for h, rslt in sp.ana_reachability.items():
            if h not in self.ana_reachability:
                self.ana_reachability[h] = rslt
                updated = True
            elif self.ana_reachability[h] != rslt:
                # 注意：直接移除冲突的结果
                del self.ana_reachability[h]
                updated = True
        for h, rslt in sp.ana_exploitability.items():
            if h not in self.ana_exploitability:
                self.ana_exploitability[h] = rslt
                updated = True
            elif self.ana_exploitability[h] != rslt:
                # 注意：直接移除冲突的结果
                del self.ana_exploitability[h]
                updated = True
        return updated

    def redis_key(self) -> str:
        """
        生成Redis缓存键
        
        Returns:
            str: Redis缓存键字符串
        """
        return f"sink#{self.coord.redis_key()}"

    def is_in_stack_frames(self, frames: List[str]) -> bool:
        """
        检查汇点是否在指定的栈帧中
        
        Args:
            frames: 栈帧字符串列表
            
        Returns:
            bool: 是否在任意栈帧中
        """
        return self.coord.is_in_stack_frames(frames)

    def exploited(self) -> bool:
        """
        检查汇点是否已被利用
        
        Returns:
            bool: 是否产生过崩溃
        """
        return len(self.crashes) > 0

    def reached(self) -> bool:
        """
        检查汇点是否已被访问
        
        Returns:
            bool: 是否被访问过
            
        注意：
            如果种子更新延迟，也要考虑崩溃情况
        """
        # 如果种子更新延迟的情况
        return len(self.beepseeds) > 0 or len(self.crashes) > 0

    def in_prio(self) -> bool:
        """
        检查汇点是否在优先级范围内
        
        优先级条件：
            - 未被利用（无崩溃）
            - 且在差异分析范围内或有关联的SARIF报告
            
        Returns:
            bool: 是否在优先级范围内
        """
        return len(self.crashes) == 0 and (self.in_diff or len(self.sarif_reports) > 0)

    def __str__(self) -> str:
        """
        汇点的字符串表示
        
        Returns:
            str: 包含汇点基本信息的字符串
        """
        return f"sink @ <{self.coord}, type:{self.type} {self.in_diff}, beepseeds: {len(self.beepseeds)}, sarif_reports: {len(self.sarif_reports)}, reached: {self.reached()}, exploited: {self.exploited()}>"

    def __repr__(self) -> str:
        """
        汇点的详细字符串表示
        
        Returns:
            str: 包含汇点详细信息的字符串
        """
        return (
            f"Sinkpoint(coord={self.coord}, "
            f"type='{self.type}', "
            f"reached={self.reached()}, "
            f"exploited={self.exploited()})"
        )


class CallGraphSource:
    """
    调用图源类
    
    表示调用图数据的来源信息，用于追踪不同工具生成的调用图数据。
    
    属性：
        tool (str): 工具名称（如joern、soot、sarif）
        version (str): 工具版本信息
    
    用途：
        - 调用图数据源追踪
        - 多工具结果整合
        - 数据质量评估
    """

    def __init__(self, tool: str, version: str):
        """
        初始化调用图源
        
        Args:
            tool: 工具名称
            version: 工具版本
        """
        self.tool = tool
        self.version = version

    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式
        
        Returns:
            dict: 包含源信息的字典
        """
        return {
            "tool": self.tool,
            "version": self.version,
        }

    @classmethod
    def frm_dict(cls, data: Dict[str, Any]) -> "CallGraphSource":
        """
        从字典创建调用图源对象
        
        Args:
            data: 包含源信息的字典
            
        Returns:
            CallGraphSource: 创建的调用图源对象
        """
        return cls(
            tool=data["tool"],
            version=data["version"],
        )

    def __hash__(self):
        return hash((self.tool, self.version))


class HarnessDiffReachability:
    """
    工具差异可访问性类
    
    表示单个测试用例的差异分析结果，包含可访问性状态和调用图源信息。
    
    属性：
        harness_name (str): 测试用例名称
        reachable (bool): 是否可访问
        cg_source (set[CallGraphSource]): 调用图源集合
    
    用途：
        - 差异分析结果管理
        - 可访问性状态跟踪
        - 多工具结果整合
    """

    def __init__(
        self, harness_name: str, reachable: bool, cg_source: set[CallGraphSource]
    ):
        """
        初始化工具差异可访问性
        
        Args:
            harness_name: 测试用例名称
            reachable: 可访问性状态
            cg_source: 调用图源集合
        """
        self.harness_name = harness_name
        self.reachable = reachable
        self.cg_source = cg_source

    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式
        
        Returns:
            dict: 包含可访问性信息的字典
        """
        return {
            "harness_name": self.harness_name,
            "reachable": self.reachable,
            "cg_source": [source.to_dict() for source in self.cg_source],
        }

    @classmethod
    def frm_dict(cls, data: Dict[str, Any]) -> "HarnessDiffReachability":
        """
        从字典创建可访问性对象
        
        Args:
            data: 包含可访问性信息的字典
            
        Returns:
            HarnessDiffReachability: 创建的可访问性对象
        """
        cg_source = [CallGraphSource.frm_dict(source) for source in data["cg_source"]]
        return cls(
            harness_name=data["harness_name"],
            reachable=data["reachable"],
            cg_source=cg_source,
        )

    def merge(self, diff: "HarnessDiffReachability") -> bool:
        """
        合并另一个可访问性对象
        
        Args:
            diff: 要合并的可访问性对象
            
        Returns:
            bool: 是否成功合并新信息
            
        合并策略：
            - 测试用例名称必须相同
            - 可访问性状态使用逻辑或
            - 调用图源信息使用集合并集
        """
        if self.harness_name != diff.harness_name:
            return False
        self.reachable = self.reachable or diff.reachable
        self.cg_source.update(diff.cg_source)
        return True


class DiffReachabilityReport:
    """
    差异可访问性报告类
    
    管理多个测试用例的差异分析结果，提供完整的可访问性状态报告。
    支持从多种数据源创建和合并报告。
    
    属性：
        h_reach_list (List[HarnessDiffReachability]): 可访问性分析结果列表
    
    用途：
        - 差异分析结果整合
        - 可访问性状态报告
        - 多工具结果比较
        - 测试优先级排序
    """

    def __init__(self, h_reach_list: List[HarnessDiffReachability] = None):
        """
        初始化差异可访问性报告
        
        Args:
            h_reach_list: 可访问性分析结果列表
        """
        self.h_reach_list = copy.deepcopy(h_reach_list) if h_reach_list else []

    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式
        
        Returns:
            dict: 以测试用例名称为键的字典
        """
        return {
            h_reach.harness_name: h_reach.to_dict() for h_reach in self.h_reach_list
        }

    def to_json(self) -> str:
        """
        转换为JSON字符串
        
        Returns:
            str: 格式化的JSON字符串
        """
        return json.dumps(self.to_dict(), indent=2)

    def get_reachable_harnesses(self) -> List[str]:
        """
        获取可访问的测试用例列表
        
        Returns:
            List[str]: 可访问的测试用例名称列表
        """
        return [
            h_reach.harness_name for h_reach in self.h_reach_list if h_reach.reachable
        ]

    def from_all_cg_sources(self) -> bool:
        """
        检查是否包含所有调用图源类型
        
        Returns:
            bool: 是否包含joern、soot、sarif三种工具
            
        用于：
            - 数据完整性验证
            - 报告质量评估
        """
        has_joern, has_soot, has_sarif = False, False, False
        for h_reach in self.h_reach_list:
            if h_reach.cg_source.tool == "joern":
                has_joern = True
            elif h_reach.cg_source.tool == "soot":
                has_soot = True
            elif h_reach.cg_source.tool == "sarif":
                has_sarif = True
        return has_joern and has_soot and has_sarif

    @classmethod
    def frm_dict(cls, data: Dict[str, Any]) -> "DiffReachabilityReport":
        """
        从字典创建报告对象
        
        Args:
            data: 包含报告数据的字典
            
        Returns:
            DiffReachabilityReport: 创建的报告对象
        """
        h_reach_list = [HarnessDiffReachability.frm_dict(h) for h in data.values()]
        return cls(h_reach_list=h_reach_list)

    @classmethod
    def frm_llmpocgen(cls, blackboard: Dict[str, Any]) -> "DiffReachabilityReport":
        """
        从LLM POC生成器的blackboard创建报告
        
        Args:
            blackboard: 包含LLM POC生成结果的blackboard字典
            
        Returns:
            DiffReachabilityReport: 创建的报告对象
            
        数据源：
            - merged_joern_cg: Joern调用图
            - merged_soot_cg: Soot调用图
            - merged_sarif_cg: SARIF调用图
            - diff.harnesses: 差异分析中的测试用例
        """
        cg_sources = []
        joern_cg_src = blackboard["merged_joern_cg"]
        soot_cg_src = blackboard["merged_soot_cg"]
        sarif_cg_src = blackboard["merged_sarif_cg"]
        if joern_cg_src != "":
            cg_sources.append(CallGraphSource(tool="joern", version=joern_cg_src))
        if soot_cg_src != "":
            cg_sources.append(CallGraphSource(tool="soot", version=soot_cg_src))
        if sarif_cg_src != "":
            cg_sources.append(CallGraphSource(tool="sarif", version=sarif_cg_src))

        h_reach_list = [
            HarnessDiffReachability(
                harness_name=harness,
                reachable=True,
                cg_source=cg_sources,
            )
            for harness in blackboard["diff"]["harnesses"]
        ]
        return cls(h_reach_list=h_reach_list)

    def merge(self, diff: "DiffReachabilityReport"):
        """
        合并另一个差异可访问性报告
        
        Args:
            diff: 要合并的报告
            
        合并策略：
            - 为每个新的可访问性结果查找匹配的现有结果
            - 如果找到匹配，调用merge方法合并
            - 如果未找到匹配，添加到列表中
        """
        for new_h in diff.h_reach_list:
            for old_h in self.h_reach_list:
                if old_h.harness_name == new_h.harness_name:
                    old_h.merge(new_h)
                    break
            else:
                self.h_reach_list.append(new_h)
