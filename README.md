# mkcert

mkcert is a simple tool for making locally-trusted development certificates. It requires no configuration.

```
$ mkcert example.com "*.example.com" example.test localhost 127.0.0.1 ::1
Using the local CA at "/Users/filippo/Library/Application Support/mkcert" ✨

Created a new certificate valid for the following names 📜
 - "example.com"
 - "*.example.com"
 - "example.test"
 - "localhost"
 - "127.0.0.1"
 - "::1"

The certificate is at "./example.com+5.pem" and the key at "./example.com+5-key.pem" ✅
```

## Installation

如果要安装本软件，请先安装Crystal编译器。并且依赖 openssl 的源码头文件，Ubuntu上可以安装 libssl-dev，CentOS上可以安装 openssl-devel

```
$ git clone https://github.com/gnuos/mkcert.git
$ cd mkcert
$ shards update
$ shards build

```

## Usage

编译后的程序在 ./bin 目录里面，执行 `./bin/mkcert` 命令如果不带参数，就会输出帮助说明。签发证书默认使用的是ECC算法，执行下面的命令会在当前目录生成证书和私钥：

mkcert 工具默认生成SAN证书，可以允许域名、IP地址、Email地址混合使用，生成的证书可以用于多种用途。mkcert 命令后面的每个名称用空格隔开，通配符需要用双引号或单引号。

```
$ ./bin/mkcert github.com "*.github.com"

```

## Development

项目的入口是 src/mkcert.cr 文件，在 src/mkcert.cr 文件中引入依赖的包，然后进行编译。
如果要修复bug或者要添加功能，应该在 src/mkcert/ 里面查找相应的代码结构。

## Contributing

1. Fork it (<https://github.com/your-github-user/mkcert/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Kevin](https://github.com/gnuos) - creator and maintainer
