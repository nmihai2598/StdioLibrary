build: libso_stdio.so

libso_stdio.so: so_stdio.o
		gcc -g so_stdio.o -shared -o libso_stdio.so

so_stdio.o: so_stdio.c
		gcc -c so_stdio.c -fPIC

clean:
		rm -f so_stdio.o libso_stdio.so
