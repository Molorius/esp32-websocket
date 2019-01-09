set(COMPONENT_SRCS 	"websocket.c" "websocket_server.c")
set(COMPONENT_ADD_INCLUDEDIRS "./include")
set(COMPONENT_REQUIRES lwip mbedtls)
register_component()