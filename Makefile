all: myhttp

myhttp: httpd.cpp
	gcc -W -Wall -o myhttp httpd.cpp -lpthread

clean:
	rm myhttp
