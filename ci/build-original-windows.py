"""Build complete upstream collectors on a Windows Actions runner."""
import pathlib,subprocess,os,re,sys,xml.etree.ElementTree as ET,json,shutil
root=pathlib.Path('original')/sys.argv[1]
proj=root/'ETWDataCollectorRedesigned.vcxproj'
ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
ET.register_namespace('',ns['m'])
tree=ET.parse(proj);tag=lambda x:'{'+ns['m']+'}'+x
vswhere=pathlib.Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-property','installationPath'],text=True).strip()
msbuild=pathlib.Path(vs)/'MSBuild/Current/Bin/MSBuild.exe'
# Original v141 binaries are compatible with the MSVC v14 ABI; use the original toolset when available.
toolset='v141' if any((pathlib.Path(vs)/'VC/Tools/MSVC').glob('14.16*')) else 'v143'
# Use dependency roots, not every nested Boost directory (Windows env limit).
includes={root.resolve()}
for d in root.rglob('*'):
    if d.is_dir() and d.name.lower() in {'include','inc'}:includes.add(d.resolve())
    if d.is_dir() and d.name.lower()=='boost':includes.add(d.parent.resolve())
libs=[p for p in root.rglob('*.lib') if 'x86' not in str(p.parent).lower()];libdirs={p.parent.resolve() for p in libs}
# Resolve project-specific aliases against libraries actually preserved from upstream.
available={p.name.lower():p.name for p in libs}
alias={'librdkafka.lib':'rdkafka.lib','librdkafkacpp.lib':'rdkafkacpp.lib','libsnappy.lib':'snappy.lib','libclamav.lib':'clamav.lib','zdll.lib':'zlib.lib'}
for node in tree.findall('.//m:AdditionalDependencies',ns):
    deps=[]
    for x in (node.text or '').split(';'):
        if x in {'','%(AdditionalDependencies)'}:deps.append(x);continue
        x=x.replace(chr(92),'/').rsplit('/',1)[-1]
        if x.lower() not in available and alias.get(x.lower()) in available:x=alias[x.lower()]
        deps.append(x)
    node.text=';'.join(deps)
for node in tree.findall('.//m:Import',ns):
    x=node.attrib.get('Project','')
    if re.match(r'[A-Za-z]:',x):
        hits=list(root.rglob(x.replace(chr(92),'/').rsplit('/',1)[-1]))
        node.attrib['Project']=str(hits[0].resolve()) if hits else '$(MSBuildThisFileDirectory)unused-private.props'
        if not hits:node.attrib['Condition']="'false'=='true'"
# Keep original vendored Boost 1.61 libraries; disable version-derived auto-link names.
for node in tree.findall('.//m:PreprocessorDefinitions',ns):node.text='BOOST_ALL_NO_LIB;'+(node.text or '')
program_options=next((p.name for p in libs if 'boost_program_options' in p.name.lower()),None)
if program_options:
    for node in tree.findall('.//m:AdditionalDependencies',ns):node.text=program_options+';'+(node.text or '')
for node in tree.findall('.//m:PlatformToolset',ns):node.text=toolset
for node in tree.findall('.//m:WindowsTargetPlatformVersion',ns):node.text='10.0'
for node in tree.findall('.//m:IncludePath',ns):node.text='$(VC_IncludePath);$(WindowsSDK_IncludePath);'+';'.join(map(str,sorted(includes)))
for node in tree.findall('.//m:LibraryPath',ns):node.text=';'.join(map(str,sorted(libdirs)))+';$(VC_LibraryPath_x64);$(WindowsSDK_LibraryPath_x64)'
props=ET.SubElement(tree.getroot(),tag('PropertyGroup'))
for key,val in {'IncludePath':'$(VC_IncludePath);$(WindowsSDK_IncludePath);'+';'.join(map(str,sorted(includes))),'LibraryPath':';'.join(map(str,sorted(libdirs)))+';$(VC_LibraryPath_x64);$(WindowsSDK_LibraryPath_x64)','OutDir':str((pathlib.Path('artifacts')/sys.argv[1]).resolve())+'\\','IntDir':str((pathlib.Path('build')/sys.argv[1]).resolve())+'\\','LinkIncremental':'false','GenerateDebugInformation':'false'}.items():ET.SubElement(props,tag(key)).text=val
# Avoid inherited private output/library paths while preserving all compiled sources.
for node in tree.findall('.//m:AdditionalIncludeDirectories',ns):node.text='%(AdditionalIncludeDirectories)'
for node in tree.findall('.//m:AdditionalLibraryDirectories',ns):node.text='%(AdditionalLibraryDirectories)'
# Compile independent translation units concurrently; source files are UTF-8 after migration.
for group in tree.findall('.//m:ItemDefinitionGroup/m:ClCompile',ns):
    node=group.find('m:AdditionalOptions',ns)
    if node is None:node=ET.SubElement(group,tag('AdditionalOptions'))
    node.text='/utf-8 /MP4 '+(node.text or '%(AdditionalOptions)')
# The upstream project creates one shared PCH from multiple source files.
# Disable PCH in CI so includes are parsed consistently in each translation unit.
for node in tree.findall('.//m:PrecompiledHeader',ns):node.text='NotUsing'
tree.write(proj,encoding='utf-8',xml_declaration=True)
missing=[]
for node in tree.findall('.//m:ClCompile',ns):
    if 'Include' in node.attrib and not(root/node.attrib['Include'].replace(chr(92),'/')).is_file():missing.append(node.attrib['Include'])
assert not missing, 'Missing upstream translation units: '+str(missing)
print(json.dumps({'module':sys.argv[1],'toolset':toolset,'libraries':len(libs),'include_directories':len(includes)}))
subprocess.run([str(msbuild),str(proj),'/m','/p:Configuration=Release','/p:Platform=x64','/p:PlatformToolset='+toolset,'/p:WindowsTargetPlatformVersion=10.0','/verbosity:minimal','/nologo'],check=True)
out=pathlib.Path('artifacts')/sys.argv[1]
for p in root.glob('*.dll'):shutil.copy2(p,out/p.name)
for p in root.glob('*'):
    if p.is_file() and p.suffix.lower() in {'.ini','.csv','.txt','.xml','.properties','.properites','.lst'}:shutil.copy2(p,out/p.name)
