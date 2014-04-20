
test: test.m GMEllipticCurveCrypto.m GMEllipticCurveCrypto.h
	llvm-gcc -Wall test.m GMEllipticCurveCrypto.m GMEllipticCurveCrypto+hash.m -o test -ObjC -framework Foundation -framework Security

clean:
	rm -f test
