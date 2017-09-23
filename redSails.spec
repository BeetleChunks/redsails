# -*- mode: python -*-

block_cipher = None

a = Analysis(['redSails.py'],
             pathex=['Z:\\redsails'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

a.binaries = a.binaries - TOC([
 ('tcl85.dll', None, None),
 ('tk85.dll', None, None)])
       
windivert = [('WinDivert64.dll','windivert/WinDivert64.dll', 'BINARY'), ('WinDivert64.sys','windivert/WinDivert64.sys', 'BINARY'),('WinDivert32.dll','windivert/WinDivert32.dll', 'BINARY'), ('WinDivert32.sys','windivert/WinDivert32.sys', 'BINARY')]
     
exe = EXE(pyz,
          a.scripts,
          a.binaries + windivert,
          name='redSails',
      icon='redsails.ico',
          debug=False,
          strip=False,
          upx=True,
          console=True )
      
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='redSails')
