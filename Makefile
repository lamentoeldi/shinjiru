proto-go:
	protoc --go_out=./ \
    		--go-grpc_out=./ \
    		--grpc-gateway_out=./ \
    		./api/proto/*.proto -I=./api/proto

.PHONY: protoc