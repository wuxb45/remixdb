# Maintainer: Xingbo Wu <wuxb45@gmail.com>

pkgname=remixdb
pkgver=0.1
pkgrel=1
pkgdesc="RemixDB Embedded Key-Value Store"
arch=('x86_64')
url="https://github.com/wuxb45/remixdb"
license=('GPL3.0')
depends=('glibc' 'liburing')
provides=('libremixdb.so')
source=("git+https://github.com/wuxb45/remixdb")
sha512sums=('SKIP')
validpgpkeys=('SKIP')

build() {
  cd "$pkgname"
  make O=r libremixdb.so
}

package() {
  cd "$pkgname"
  make PREFIX="$pkgdir" install
}
