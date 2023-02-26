PORTNAME=	edb-debugger
PORTVERSION=	1.3.0
CATEGORIES=	devel

MAINTAINER=	arrowd@FreeBSD.org
COMMENT=	Cross-platform AArch32/x86/x86-64 debugger
WWW=		https://github.com/eteran/edb-debugger

LICENSE=	GPLv2
LICENSE_FILE=	${WRKSRC}/COPYING

ONLY_FOR_ARCHS=	amd64 arm i386

LIB_DEPENDS=	libcapstone.so:devel/capstone4 \
		libdouble-conversion.so:devel/double-conversion \
		libgvc.so:graphics/graphviz

USES=		cmake desktop-file-utils qt:5

USE_QT=		core gui network svg widgets xml xmlpatterns buildtools:build \
		qmake:build

USE_GITHUB=	yes
GH_ACCOUNT=	eteran
GH_PROJECT=	${PORTNAME} qhexview:qhexview
GH_TAGNAME=	${PORTVERSION} 1.2.2:qhexview

CMAKE_ARGS=	-D CMAKE_REQUIRED_INCLUDES="${LOCALBASE}/include"

post-extract:
	${RM} -r ${WRKSRC}/src/qhexview
	${MV} ${WRKSRC_qhexview}/ ${WRKSRC}/src/qhexview

.include <bsd.port.mk>
