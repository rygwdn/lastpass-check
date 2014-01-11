# -*- mode: python -*-
a = Analysis(['lastpass-check.py'],
             hiddenimports=[],
             hookspath=['./hooks/'],
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='lastpass-check',
          debug=False,
          strip=None,
          upx=True,
          console=True )
