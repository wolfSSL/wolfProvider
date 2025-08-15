AC_INIT([libdefault], [1.0], [support@wolfssl.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AM_PROG_AR
LT_INIT

# Replace flag to choose between wp_default_replace.c and wp_default_stub.c
AC_ARG_ENABLE([replace],
    [AS_HELP_STRING([--enable-replace],[Build wp_default_replace.c instead of wp_default_stub.c (default: disabled).])],
    [ ENABLED_REPLACE=yes ],
    [ ENABLED_REPLACE=no ]
    )

# OpenSSL path configuration
AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl=DIR],[Specify the path to OpenSSL source code (default: system default)])],
    [ OPENSSL_DIR=$withval ],
    [ OPENSSL_DIR="" ]
    )

# Check for OpenSSL headers
if test "x$OPENSSL_DIR" != "x"; then
    # User specified OpenSSL directory
    CPPFLAGS_save=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS -I$OPENSSL_DIR/include"
    AC_CHECK_HEADER([openssl/ssl.h],
        [AC_MSG_RESULT([OpenSSL headers found in $OPENSSL_DIR])],
        [AC_MSG_ERROR([OpenSSL headers not found in $OPENSSL_DIR/include])]
    )
    CPPFLAGS=$CPPFLAGS_save
else
    # Check system default location
    AC_CHECK_HEADER([openssl/ssl.h],
        [AC_MSG_RESULT([OpenSSL headers found in system location])],
        [AC_MSG_ERROR([OpenSSL headers not found. Please install OpenSSL development package or specify path with --with-openssl=DIR])]
    )
fi

AM_CONDITIONAL([BUILD_REPLACE], [test "x$ENABLED_REPLACE" = "xyes"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
