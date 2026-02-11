# Obsidian 검증자(Validator) 실행 가이드

Obsidian 네트워크의 검증자 노드를 설정하고 운영하는 방법을 안내합니다.

## 목차

- [시스템 요구사항](#시스템-요구사항)
- [사전 준비](#사전-준비)
- [소스 빌드로 실행](#소스-빌드로-실행)
- [Docker로 실행](#docker로-실행)
- [검증자 등록](#검증자-등록)
- [노드 운영](#노드-운영)
- [문제 해결](#문제-해결)

---

## 시스템 요구사항

| 항목 | 최소 사양 | 권장 사양 |
| :--- | :--- | :--- |
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 8 GB | 16+ GB |
| **Storage** | 256 GB SSD | 512+ GB NVMe SSD |
| **Network** | 25 Mbps | 100+ Mbps |
| **OS** | Ubuntu 20.04+ / Debian 11+ | Ubuntu 22.04 LTS |

---

## 사전 준비

### 1. 계정 생성

검증자로 사용할 계정을 생성합니다:

```shell
geth account new --datadir /data/obsidian
```

비밀번호를 설정하면 계정 주소가 출력됩니다. **키스토어 파일과 비밀번호를 안전하게 백업하세요.**

### 2. OBS 토큰 확보

검증자로 참여하려면 스테이킹에 필요한 OBS 토큰이 있어야 합니다.

---

## 소스 빌드로 실행

### 빌드

```shell
# Go 1.24 이상 필요
git clone https://github.com/obsidian-protocol/go-obsidian.git
cd go-obsidian
make geth
```

빌드된 바이너리는 `build/bin/geth`에 생성됩니다.

### 노드 시작

```shell
geth \
  --datadir /data/obsidian \
  --networkid 1719 \
  --port 30303 \
  --http \
  --http.addr "0.0.0.0" \
  --http.port 8545 \
  --http.api "eth,net,web3,personal,txpool" \
  --http.corsdomain "*" \
  --ws \
  --ws.addr "0.0.0.0" \
  --ws.port 8546 \
  --syncmode "full" \
  --mine \
  --miner.etherbase "0xYOUR_VALIDATOR_ADDRESS" \
  --unlock "0xYOUR_VALIDATOR_ADDRESS" \
  --password /path/to/password.txt \
  --allow-insecure-unlock
```

> ⚠️ 프로덕션 환경에서는 `--http.corsdomain`과 `--allow-insecure-unlock`을 적절히 제한하세요.

---

## Docker로 실행

### 기본 실행

```shell
docker run -d \
  --name obsidian-validator \
  --restart unless-stopped \
  -v /data/obsidian:/root \
  -p 8545:8545 \
  -p 8546:8546 \
  -p 30303:30303 \
  -p 30303:30303/udp \
  yuchanshin/go-obsidian:latest \
  --networkid 1719 \
  --http \
  --http.addr "0.0.0.0" \
  --http.port 8545 \
  --http.api "eth,net,web3,personal,txpool" \
  --ws \
  --ws.addr "0.0.0.0" \
  --ws.port 8546 \
  --syncmode "full" \
  --mine \
  --miner.etherbase "0xYOUR_VALIDATOR_ADDRESS" \
  --unlock "0xYOUR_VALIDATOR_ADDRESS" \
  --password /root/password.txt \
  --allow-insecure-unlock
```

### Docker Compose

`docker-compose.yml` 파일을 생성합니다:

```yaml
version: "3.8"

services:
  obsidian-validator:
    image: yuchanshin/go-obsidian:latest
    container_name: obsidian-validator
    restart: unless-stopped
    ports:
      - "8545:8545"
      - "8546:8546"
      - "30303:30303"
      - "30303:30303/udp"
    volumes:
      - obsidian-data:/root
    command:
      - "--networkid=1719"
      - "--http"
      - "--http.addr=0.0.0.0"
      - "--http.port=8545"
      - "--http.api=eth,net,web3,personal,txpool"
      - "--ws"
      - "--ws.addr=0.0.0.0"
      - "--ws.port=8546"
      - "--syncmode=full"
      - "--mine"
      - "--miner.etherbase=0xYOUR_VALIDATOR_ADDRESS"
      - "--unlock=0xYOUR_VALIDATOR_ADDRESS"
      - "--password=/root/password.txt"
      - "--allow-insecure-unlock"

volumes:
  obsidian-data:
```

```shell
docker compose up -d
```

### Docker에서 계정 생성

```shell
docker run --rm -it \
  -v /data/obsidian:/root \
  yuchanshin/go-obsidian:latest \
  account new
```

---

## 검증자 등록

### 1. 노드 동기화 확인

노드가 최신 블록까지 동기화되었는지 확인합니다:

```shell
# JSON-RPC로 확인
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}'
```

`false`가 반환되면 동기화가 완료된 것입니다.

### 2. 피어 연결 확인

```shell
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'
```

### 3. 검증자 상태 확인

```shell
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_mining","params":[],"id":1}'
```

---

## 노드 운영

### 로그 확인

```shell
# 소스 빌드 실행 시
tail -f /data/obsidian/geth.log

# Docker 실행 시
docker logs -f obsidian-validator
```

### 노드 업데이트

**소스 빌드:**
```shell
cd go-obsidian
git pull origin main
make geth
# geth 재시작
```

**Docker:**
```shell
docker pull yuchanshin/go-obsidian:latest
docker compose down
docker compose up -d
```

### 백업

정기적으로 키스토어와 체인 데이터를 백업하세요:

```shell
# 키스토어 백업 (필수)
cp -r /data/obsidian/keystore /backup/keystore

# 체인 데이터 백업 (선택)
geth --datadir /data/obsidian export /backup/chain-export.gz
```

---

## 문제 해결

### 피어를 찾지 못하는 경우

- 방화벽에서 포트 `30303` (TCP/UDP)이 열려있는지 확인
- bootnodes 옵션을 추가하여 알려진 노드에 연결

```shell
geth --bootnodes "enode://BOOTNODE_ENODE_URL@IP:PORT"
```

### 동기화가 느린 경우

- `--syncmode "snap"` 옵션으로 빠른 동기화 시도 (초기 동기화 후 full로 전환)
- 디스크 I/O 성능 확인 (NVMe SSD 권장)
- `--cache 4096` 옵션으로 캐시 크기 증가

### Docker 컨테이너가 재시작되는 경우

```shell
# 로그 확인
docker logs --tail 100 obsidian-validator

# 리소스 사용량 확인
docker stats obsidian-validator
```

---

## 네트워크 정보

| 항목 | 값 |
| :--- | :--- |
| **Chain ID** | 1719 |
| **토큰** | Obsidian (OBS) |
| **합의 엔진** | Tendermint PoS |
| **블록 시간** | 2초 |
| **에포크** | 30,000 블록 (~16.7시간) |
| **RPC (HTTP)** | `http://localhost:8545` |
| **RPC (WebSocket)** | `ws://localhost:8546` |
| **P2P 포트** | 30303 |

---

## 참고 자료

- [Go Obsidian GitHub](https://github.com/obsidian-protocol/go-obsidian)
- [Docker Hub](https://hub.docker.com/r/yuchanshin/go-obsidian)
