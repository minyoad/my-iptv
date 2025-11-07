# 📺 My-IPTV - 个人IPTV项目

## 🎯 核心功能

### 1. EPG数据整合
- 自动从多个EPG源获取节目数据
- 智能去重和数据清洗
- 生成标准XMLTV格式文件

### 2. 频道管理
- 频道名称标准化处理
- 支持别名映射配置
- ISP运营商分类管理

### 3. 自动更新
- GitHub Actions每日自动更新
- 智能提交历史管理
- 支持手动触发更新

### 4. 数据处理
- 多编码格式支持(UTF-8/GBK等)
- XML格式自动修复
- 时区自动转换

## 📁 主要文件
- `epg_integrator.py` - EPG整合主程序
- `config/epg.txt` - EPG数据源配置
- `config/channel_alias.txt` - 频道别名映射
- `epg/e.xml` - 整合后的EPG数据
- `.github/workflows/update_epg.yml` - 自动更新工作流

## 🚀 使用方式
1. 配置EPG数据源
2. 设置频道别名（可选）
3. 运行 `python epg_integrator.py`
4. 或通过GitHub Actions自动更新

## 📊 输出格式
- XML格式EPG数据
- 压缩的XML.GZ格式
- 支持多种IPTV播放器