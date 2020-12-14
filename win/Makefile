build: so_stdio.obj
	link /nologo /dll /out:so_stdio.dll so_stdio.obj

so_stdio.obj: so_stdio.c
	cl /nologo /MD /W3 /D_CRT_SECURE_NO_DEPRECATE /c so_stdio.c

clean:
	del so_stdio.obj so_stdio.dll so_stdio.exp so_stdio.lib