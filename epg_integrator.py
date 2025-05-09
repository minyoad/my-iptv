#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import requests
import xml.etree.ElementTree as ET
import gzip
import logging
from datetime import datetime
import re

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 项目路径
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(PROJECT_DIR, 'config')
EPG_DIR = os.path.join(PROJECT_DIR, 'epg')

# 确保EPG目录存在
if not os.path.exists(EPG_DIR):
    os.makedirs(EPG_DIR)

# 输出文件路径
OUTPUT_XML = os.path.join(EPG_DIR, 'e.xml')
OUTPUT_XML_GZ = os.path.join(EPG_DIR, 'e.xml.gz')

# 频道别名映射
def load_channel_aliases(alias_file):
    """加载频道别名映射"""
    aliases = {}
    try:
        with open(alias_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if len(parts) >= 2:
                    template_name = parts[0]
                    for alias in parts:
                        aliases[alias] = template_name
        logger.info(f"已加载 {len(aliases)} 个频道别名映射")
        return aliases
    except Exception as e:
        logger.error(f"加载频道别名文件失败: {e}")
        return {}

# 下载EPG源
def download_epg_source(url):
    """下载EPG源文件"""
    try:
        logger.info(f"正在下载EPG源: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # 获取内容类型和编码
        content_type = response.headers.get('Content-Type', '')
        encoding = None
        
        # 从Content-Type头中提取编码
        if 'charset=' in content_type:
            encoding = content_type.split('charset=')[-1].strip()
            # 规范化编码名称
            encoding = encoding.lower().replace('-', '')
            logger.info(f"从Content-Type获取到编码: {encoding}")
        
        # 如果没有指定编码，尝试从内容中检测
        if not encoding:
            # 尝试从XML声明中获取编码
            content_start = response.content[:1000].decode('utf-8', errors='ignore')
            encoding_match = re.search(r'encoding=["\']([^"\']*)["\']', content_start)
            if encoding_match:
                encoding = encoding_match.group(1).lower().replace('-', '')
                logger.info(f"从XML声明获取到编码: {encoding}")
        
        # 编码映射表，处理一些常见的编码别名
        encoding_map = {
            'utf8': 'utf-8',
            'gbk': 'gbk',
            'gb2312': 'gb2312',
            'gb18030': 'gb18030',
            'big5': 'big5',
            'ascii': 'ascii'
        }
        
        # 规范化编码名称
        if encoding:
            encoding = encoding_map.get(encoding, encoding)
        
        # 如果仍然没有找到编码，或者编码无效，使用常见的编码尝试解码
        if not encoding or encoding not in encoding_map.values():
            encodings_to_try = ['utf-8', 'gbk', 'gb2312', 'gb18030', 'big5']
            logger.info(f"尝试使用常见编码解析内容: {', '.join(encodings_to_try)}")
            
            # 保存解码结果和对应的错误数量
            best_result = None
            min_errors = float('inf')
            
            for enc in encodings_to_try:
                try:
                    # 尝试解码，计算错误字符数量
                    decoded = response.content.decode(enc, errors='ignore')
                    error_count = len(response.content) - len(decoded.encode(enc, errors='ignore'))
                    
                    if error_count < min_errors:
                        min_errors = error_count
                        best_result = decoded
                        encoding = enc
                        
                        # 如果没有错误，直接使用这个编码
                        if error_count == 0:
                            logger.info(f"找到完全匹配的编码: {enc}")
                            break
                except UnicodeDecodeError:
                    continue
            
            # 使用最佳匹配的编码结果
            if best_result:
                logger.info(f"使用最佳匹配编码 {encoding} 解析EPG源，错误字符数: {min_errors}")
                return best_result
            else:
                # 如果所有编码都失败，使用utf-8并忽略错误
                logger.warning(f"无法确定EPG源的编码，使用UTF-8并忽略错误: {url}")
                return response.content.decode('utf-8', errors='ignore')
        
        # 使用检测到的编码
        logger.info(f"使用编码 {encoding} 解析EPG源: {url}")
        return response.content.decode(encoding, errors='ignore')
    except Exception as e:
        logger.error(f"下载EPG源失败 {url}: {e}")
        return None

# 解析XML
def parse_epg_xml(xml_content):
    """解析EPG XML内容"""
    if not xml_content:
        logger.error("XML内容为空，无法解析")
        return None
        
    try:
        # 尝试直接解析XML
        try:
            root = ET.fromstring(xml_content)
            return root
        except ET.ParseError as e:
            logger.warning(f"初次解析XML失败，尝试修复: {e}")
            
            # 尝试修复常见的XML问题
            # 1. 替换非法XML字符
            xml_content = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', xml_content)
            
            # 2. 确保XML声明正确
            if not xml_content.strip().startswith('<?xml'):
                xml_content = '<?xml version="1.0" encoding="utf-8"?>\n' + xml_content
            else:
                # 确保XML声明使用UTF-8编码
                xml_content = re.sub(r'<\?xml[^>]*encoding=["\']([^"\']*)["\'][^>]*\?>',
                                    '<?xml version="1.0" encoding="utf-8"?>', xml_content)
            
            # 3. 修复未闭合的CDATA标签
            xml_content = re.sub(r'<!\[CDATA\[([^\]]*?)(?!\]\]>)', r'<!\[CDATA\[\1]]>', xml_content)
            
            # 4. 修复特殊字符
            xml_content = xml_content.replace('&', '&amp;')
            # 但保留已经正确的实体引用
            xml_content = xml_content.replace('&amp;amp;', '&amp;')
            xml_content = xml_content.replace('&amp;lt;', '&lt;')
            xml_content = xml_content.replace('&amp;gt;', '&gt;')
            xml_content = xml_content.replace('&amp;quot;', '&quot;')
            xml_content = xml_content.replace('&amp;apos;', '&apos;')
            
            # 5. 修复未闭合的标签
            # 这里只是一个简单的示例，实际上很难通用地修复所有未闭合标签
            common_tags = ['title', 'desc', 'category', 'display-name']
            for tag in common_tags:
                # 查找没有闭合的标签
                xml_content = re.sub(f'<{tag}([^>]*)>([^<]*?)(?!<\/{tag}>)',
                                    f'<{tag}\\1>\\2</{tag}>', xml_content)
            
            # 尝试再次解析
            try:
                root = ET.fromstring(xml_content)
                logger.info("成功修复并解析XML")
                return root
            except ET.ParseError as e2:
                logger.warning(f"修复后仍然无法解析XML: {e2}，尝试使用更严格的修复方法")
                
                # 使用更严格的方法：移除所有可能导致问题的标签
                # 这是一种最后的尝试，可能会丢失一些数据
                try:
                    # 提取<tv>标签内容
                    tv_match = re.search(r'<tv[^>]*>(.*?)</tv>', xml_content, re.DOTALL)
                    if tv_match:
                        tv_content = tv_match.group(0)
                        # 创建一个新的、干净的XML
                        clean_xml = f'<?xml version="1.0" encoding="utf-8"?>\n{tv_content}'
                        root = ET.fromstring(clean_xml)
                        logger.info("使用严格修复方法成功解析XML")
                        return root
                except Exception:
                    pass
                    
                logger.error("所有修复方法都失败")
                return None
    except Exception as e:
        logger.error(f"解析XML失败: {e}")
        return None

# 规范化频道名称
def normalize_channel_name(name, aliases):
    """根据别名映射规范化频道名称"""
    return aliases.get(name, name)

# 整合EPG数据
def integrate_epg_data(epg_sources, aliases):
    """整合多个EPG源的数据"""
    # 创建新的XML根元素
    tv_element = ET.Element('tv')
    tv_element.set('generator-info-name', 'EPG Integrator')
    tv_element.set('generator-info-url', 'https://github.com/user/my-iptv')
    tv_element.set('date', datetime.now().strftime('%Y-%m-%d'))
    
    # 用于跟踪已处理的频道和节目
    processed_channels = set()
    processed_programmes = set()  # 使用节目ID+开始时间作为唯一标识
    
    # 处理每个EPG源
    for source_url in epg_sources:
        logger.info(f"开始处理EPG源: {source_url}")
        xml_content = download_epg_source(source_url)
        if not xml_content:
            logger.warning(f"无法获取EPG源内容: {source_url}")
            continue
            
        root = parse_epg_xml(xml_content)
        if root is None:
            logger.warning(f"无法解析EPG源XML: {source_url}")
            continue
        
        # 处理频道信息
        channel_count = 0
        for channel in root.findall('./channel'):
            try:
                channel_id = channel.get('id')
                if not channel_id:
                    logger.warning("跳过没有ID的频道")
                    continue
                    
                display_name = None
                
                # 获取频道显示名称
                for name_elem in channel.findall('./display-name'):
                    if name_elem.text:
                        # 确保频道名称是有效的UTF-8字符串
                        try:
                            display_name = name_elem.text
                            # 测试是否可以正确编码解码
                            display_name.encode('utf-8').decode('utf-8')
                        except UnicodeError:
                            # 如果有编码问题，尝试修复
                            display_name = name_elem.text.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
                            logger.debug(f"修复频道名称编码: {display_name}")
                        break
                
                if not display_name:
                    logger.warning(f"跳过没有显示名称的频道: {channel_id}")
                    continue
                    
                # 规范化频道名称
                normalized_name = normalize_channel_name(display_name, aliases)
                
                # 如果该频道已处理过，则跳过
                channel_key = f"{normalized_name}_{channel_id}"
                if channel_key in processed_channels:
                    continue
                    
                # 创建新的频道元素
                new_channel = ET.SubElement(tv_element, 'channel', id=channel_id)
                ET.SubElement(new_channel, 'display-name').text = normalized_name
                
                # 复制其他子元素（如图标等）
                for child in channel:
                    if child.tag != 'display-name':
                        try:
                            # 处理子元素的文本内容
                            if child.text and not isinstance(child.text, str):
                                child.text = str(child.text)
                            
                            # 处理子元素的属性
                            for attr_name, attr_value in child.attrib.items():
                                if not isinstance(attr_value, str):
                                    child.attrib[attr_name] = str(attr_value)
                            
                            # 使用深拷贝方式添加子元素
                            new_child = ET.SubElement(new_channel, child.tag, child.attrib)
                            if child.text:
                                new_child.text = child.text
                                
                            # 递归复制所有子元素的子元素
                            for grandchild in child:
                                ET.SubElement(new_child, grandchild.tag, grandchild.attrib).text = grandchild.text
                        except Exception as e:
                            logger.warning(f"复制频道子元素失败: {e}")
                            continue
                
                processed_channels.add(channel_key)
                channel_count += 1
            except Exception as e:
                logger.warning(f"处理频道信息失败: {e}")
                continue
        
        logger.info(f"从 {source_url} 处理了 {channel_count} 个频道")
        
        # 处理节目信息
        programme_count = 0
        for programme in root.findall('./programme'):
            try:
                channel_id = programme.get('channel')
                start_time = programme.get('start')
                
                if not channel_id or not start_time:
                    continue
                
                # 创建唯一标识
                programme_key = f"{channel_id}_{start_time}"
                
                # 如果该节目已处理过，则跳过
                if programme_key in processed_programmes:
                    continue
                
                # 处理所有文本元素，确保编码正确
                for elem in programme.iter():
                    if elem.text:
                        try:
                            # 测试是否可以正确编码解码
                            elem.text.encode('utf-8').decode('utf-8')
                        except UnicodeError:
                            # 如果有编码问题，尝试修复
                            elem.text = elem.text.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
                            
                    # 处理属性值
                    for attr_name, attr_value in elem.attrib.items():
                        if attr_value:
                            try:
                                # 测试是否可以正确编码解码
                                attr_value.encode('utf-8').decode('utf-8')
                            except UnicodeError:
                                # 如果有编码问题，尝试修复
                                elem.attrib[attr_name] = attr_value.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
                
                # 创建新的节目元素并复制所有属性
                new_programme = ET.SubElement(tv_element, 'programme', programme.attrib)
                
                # 复制所有子元素
                for child in programme:
                    try:
                        # 创建子元素
                        new_child = ET.SubElement(new_programme, child.tag, child.attrib)
                        if child.text:
                            new_child.text = child.text
                            
                        # 递归复制所有子元素的子元素
                        for grandchild in child:
                            ET.SubElement(new_child, grandchild.tag, grandchild.attrib).text = grandchild.text
                    except Exception as e:
                        logger.warning(f"复制节目子元素失败: {e}")
                        continue
                
                processed_programmes.add(programme_key)
                programme_count += 1
            except Exception as e:
                logger.warning(f"处理节目信息失败: {e}")
                continue
                
        logger.info(f"从 {source_url} 处理了 {programme_count} 个节目")
    
    logger.info(f"已整合 {len(processed_channels)} 个频道和 {len(processed_programmes)} 个节目")
    return tv_element

# 保存XML
def save_xml(root, output_file):
    """保存XML到文件"""
    try:
        # 确保所有节点的文本内容都是有效的字符串
        for elem in root.iter():
            # 处理文本内容
            if elem.text is not None:
                if not isinstance(elem.text, str):
                    try:
                        elem.text = elem.text.decode('utf-8', errors='ignore')
                    except (UnicodeError, AttributeError):
                        elem.text = str(elem.text)
                
                # 确保文本不包含非法XML字符
                elem.text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', elem.text)
            
            # 处理属性值
            for attr_name, attr_value in elem.attrib.items():
                if attr_value is not None and not isinstance(attr_value, str):
                    try:
                        elem.attrib[attr_name] = attr_value.decode('utf-8', errors='ignore')
                    except (UnicodeError, AttributeError):
                        elem.attrib[attr_name] = str(attr_value)
                
                # 确保属性值不包含非法XML字符
                if attr_value is not None:
                    elem.attrib[attr_name] = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', elem.attrib[attr_name])
        
        # 生成XML字符串，使用minidom格式化XML以提高可读性
        try:
            # 尝试使用minidom格式化XML
            from xml.dom import minidom
            rough_string = ET.tostring(root, encoding='utf-8', method='xml')
            reparsed = minidom.parseString(rough_string)
            xml_str = reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')
            # 移除XML声明行，因为我们将在后面添加
            xml_str = re.sub(r'^<\?xml[^>]*\?>\n', '', xml_str)
            # 添加我们自己的XML声明
            xml_str = '<?xml version="1.0" encoding="utf-8"?>\n' + xml_str
            # 移除多余的空行
            xml_str = re.sub(r'\n\s*\n', '\n', xml_str)
        except Exception as format_error:
            logger.warning(f"格式化XML失败，使用默认格式: {format_error}")
            # 确保不会有重复的XML声明
            xml_str = '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding='unicode', method='xml')
        
        # 直接写入文件，确保使用UTF-8编码，并添加BOM标记以确保某些应用能正确识别UTF-8
        with open(output_file, 'w', encoding='utf-8-sig') as f:
            f.write(xml_str)
        
        # 验证生成的XML文件
        try:
            with open(output_file, 'r', encoding='utf-8-sig') as f:
                content = f.read()
                ET.fromstring(content)
            logger.info(f"已验证生成的XML文件格式正确")
        except Exception as validate_error:
            logger.warning(f"生成的XML文件验证失败，但文件已保存: {validate_error}")
            
        logger.info(f"已保存整合后的EPG到 {output_file}")
        return True
    except Exception as e:
        logger.error(f"保存XML失败: {e}")
        return False

# 压缩XML
def compress_xml(input_file, output_file):
    """将XML压缩为gzip格式"""
    try:
        # 检查输入文件是否存在
        if not os.path.exists(input_file):
            logger.error(f"要压缩的文件不存在: {input_file}")
            return False
            
        # 获取文件大小
        input_size = os.path.getsize(input_file)
        logger.info(f"原始XML文件大小: {input_size/1024:.2f} KB")
        
        # 读取文件并压缩
        with open(input_file, 'rb') as f_in:
            content = f_in.read()
            
            # 确保内容是有效的XML
            try:
                # 尝试解析XML以验证其有效性
                from xml.dom import minidom
                minidom.parseString(content)
                logger.info("XML内容有效，开始压缩")
            except Exception as xml_error:
                logger.warning(f"XML内容可能存在问题，但仍继续压缩: {xml_error}")
            
            # 使用最高压缩级别
            with gzip.open(output_file, 'wb', compresslevel=9) as f_out:
                f_out.write(content)
        
        # 检查压缩后的文件
        if os.path.exists(output_file):
            output_size = os.path.getsize(output_file)
            compression_ratio = (1 - output_size/input_size) * 100 if input_size > 0 else 0
            logger.info(f"压缩后文件大小: {output_size/1024:.2f} KB，压缩率: {compression_ratio:.2f}%")
            
            # 验证压缩文件是否可以正常解压
            try:
                with gzip.open(output_file, 'rb') as test_file:
                    # 只读取一小部分来测试
                    test_content = test_file.read(1024)
                    if len(test_content) > 0:
                        logger.info("压缩文件验证成功，可以正常解压")
                    else:
                        logger.warning("压缩文件可能为空")
            except Exception as test_error:
                logger.warning(f"压缩文件验证失败: {test_error}")
            
            return True
        else:
            logger.error(f"压缩后的文件不存在: {output_file}")
            return False
    except Exception as e:
        logger.error(f"压缩XML失败: {e}")
        return False

# 主函数
def main():
    # 加载配置
    epg_sources_file = os.path.join(CONFIG_DIR, 'epg.txt')
    channel_alias_file = os.path.join(CONFIG_DIR, 'channel_alias.txt')
    
    # 检查文件是否存在
    if not os.path.exists(epg_sources_file):
        logger.error(f"EPG源文件不存在: {epg_sources_file}")
        return False
    
    if not os.path.exists(channel_alias_file):
        logger.error(f"频道别名文件不存在: {channel_alias_file}")
        return False
    
    # 加载EPG源
    with open(epg_sources_file, 'r', encoding='utf-8') as f:
        epg_sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not epg_sources:
        logger.error("没有找到有效的EPG源")
        return False
    
    logger.info(f"已加载 {len(epg_sources)} 个EPG源")
    
    # 加载频道别名
    aliases = load_channel_aliases(channel_alias_file)
    
    # 整合EPG数据
    integrated_epg = integrate_epg_data(epg_sources, aliases)
    
    # 保存结果
    if integrated_epg is not None:
        if save_xml(integrated_epg, OUTPUT_XML):
            compress_xml(OUTPUT_XML, OUTPUT_XML_GZ)
            logger.info("EPG整合完成")
            return True
    
    logger.error("EPG整合失败")
    return False

if __name__ == "__main__":
    start_time = datetime.now()
    success = main()
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    if success:
        logger.info(f"处理完成，耗时 {duration:.2f} 秒")
        sys.exit(0)
    else:
        logger.error(f"处理失败，耗时 {duration:.2f} 秒")
        sys.exit(1)