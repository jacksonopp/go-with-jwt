FROM golang:1.21

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

RUN go install github.com/a-h/templ/cmd/templ@latest

COPY . .

RUN apt-get update && apt-get install -y make

RUN make build

EXPOSE 3000

CMD [ "./main" ]