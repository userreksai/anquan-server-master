package server

import "time"

func beijingNotificationTime(at time.Time) string {
	return at.In(beijingTimeZone).Format("2006-01-02 15:04:05")
}

// Keep protocol identifiers beside their translated labels for troubleshooting.
func notificationLabel(value string, labels map[string]string) string {
	if label, ok := labels[value]; ok {
		return label + "（" + value + "）"
	}
	return value
}

func securitySourceLabel(source string) string {
	return notificationLabel(source, map[string]string{
		"auditd":     "Linux 审计",
		"tetragon":   "Tetragon 运行时安全",
		"sudo":       "sudo 操作审计",
		"policies":   "系统策略",
		"security":   "安全采集器",
		"native_fim": "实时文件监控",
		"ssh_auth":   "SSH 认证监控",
		"task":       "任务执行记录",
	})
}

func securityKindLabel(kind string) string {
	return notificationLabel(kind, map[string]string{
		"policy_check":       "策略合规检查",
		"collector_error":    "采集器异常",
		"parse_error":        "日志解析异常",
		"oversize_event":     "事件超过传输大小限制",
		"oversize_record":    "日志记录超过大小限制",
		"collection_gap":     "日志采集中断",
		"runtime":            "运行时事件",
		"process_exec":       "进程执行",
		"process_exit":       "进程退出",
		"process_kprobe":     "内核函数跟踪",
		"process_tracepoint": "内核跟踪点事件",
		"process_uprobe":     "用户态函数跟踪",
		"process_usdt":       "用户态静态跟踪",
		"process_loader":     "进程加载事件",
		"process_lsm":        "内核安全模块事件",
		"audit":              "系统审计记录",
		"exec":               "外部程序执行",
		"file_change":        "文件发生变化",
		"file_activity":      "文件活动记录",
		"ssh_auth_failure":   "SSH 认证失败",
		"ssh_bruteforce":     "SSH 失败认证达到阈值",
		"task_started":       "计划任务开始执行",
		"task_finished":      "计划任务执行成功",
		"task_failed":        "计划任务执行失败",
		"command":            "sudo 命令记录",
		"io_session":         "sudo 输入输出会话索引",
		"io_limit":           "sudo 录制大小超限",
		"io_chunk":           "sudo 录制数据上传",
	})
}

func securitySeverityLabel(severity string) string {
	return notificationLabel(severity, map[string]string{
		"debug":    "调试",
		"info":     "信息",
		"notice":   "提示",
		"warning":  "警告",
		"error":    "错误",
		"critical": "严重",
	})
}

// Translate only messages emitted by known Agent versions. Custom messages and
// diagnostic errors stay intact, including messages from newer Agent versions.
func securityNotificationMessage(source, kind, message string) string {
	translate := func(english, chinese string) string {
		if message == english {
			return chinese
		}
		return message
	}
	switch source + "/" + kind {
	case "policies/policy_check":
		return translate("Host policy compliance checked", "已完成主机策略合规检查")
	case "auditd/oversize_event", "tetragon/oversize_event", "sudo/oversize_event", "policies/oversize_event":
		return translate("Event exceeds transport size; original records remain in the host source log", "事件超过传输大小限制，原始记录保留在主机源日志中")
	case "tetragon/parse_error":
		return translate("Tetragon emitted invalid JSON", "Tetragon 输出的 JSON 格式无效")
	case "auditd/oversize_record", "tetragon/oversize_record", "sudo/oversize_record":
		return translate("Log record exceeds 128KiB; original remains in the host source log", "日志记录超过 128 KiB，原始记录保留在主机源日志中")
	case "auditd/collection_gap", "tetragon/collection_gap", "sudo/collection_gap":
		switch message {
		case "Rotated source disappeared before it could be drained":
			return "轮转后的源日志在读取完成前已消失"
		case "Source was truncated; continuing from the beginning":
			return "源日志已被截断，将从头继续读取"
		case "Source contents changed before the saved cursor":
			return "已保存读取位置之前的源日志内容发生变化"
		}
	case "sudo/io_session":
		return translate("sudo input/output session index", "sudo 输入输出会话索引")
	case "sudo/io_limit":
		switch message {
		case "sudo I/O session exceeds max_session_bytes":
			return "sudo 输入输出会话超过配置的最大字节数（max_session_bytes）"
		case "sudo I/O file exceeds 64MiB transport limit":
			return "sudo 输入输出文件超过 64 MiB 传输限制"
		}
	case "sudo/io_chunk":
		return translate("sudo I/O file data", "sudo 输入输出文件数据")
	case "ssh_auth/ssh_auth_failure":
		return translate("SSH authentication failed", "SSH 认证失败")
	case "ssh_auth/ssh_bruteforce":
		return translate("repeated SSH authentication failures", "检测到重复 SSH 认证失败")
	case "task/task_started":
		return translate("Scheduled task started", "计划任务开始执行")
	case "task/task_finished":
		return translate("Scheduled task finished", "计划任务执行成功")
	case "task/task_failed":
		return translate("Scheduled task failed", "计划任务执行失败")
	case "native_fim/file_activity":
		return translate("kernel file notification", "内核文件活动通知")
	case "native_fim/file_change":
		switch message {
		case "monitored file added":
			return "新增监控文件"
		case "monitored file deleted":
			return "监控文件已删除"
		case "monitored file modified":
			return "监控文件内容已修改"
		case "monitored file missing":
			return "监控文件不存在"
		}
	}
	if source == "auditd" && message == "Linux audit "+kind {
		return "Linux 审计：" + securityKindLabel(kind)
	}
	if source == "tetragon" && message == "Tetragon "+kind {
		return "Tetragon 事件：" + securityKindLabel(kind)
	}
	return message
}
