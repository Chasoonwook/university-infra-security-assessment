# 네트워크 보안 관점 — 라우팅 DDoS와 제어 평면(Control Plane) 보호

[← README로 돌아가기](../README.md)

> SCN-03은 내부 PC 감염을 이용해 **전산망 이중화(HSRP) 게이트웨이의 제어 평면**까지 영향을 준 네트워크 가용성 침해 시나리오입니다. 이 문서는 공격 재현이 아니라, **"왜 내부 호스트의 트래픽이 게이트웨이 제어 평면까지 도달했는가"** 와 **"네트워크 계층에서 어떻게 막는가"** 를 정리한 방어 관점 분석입니다.
>
> 모든 내용은 승인된 격리 실습 환경(가상 네트워크)을 기준으로 하며, 설정 예시는 실제 장비 구성이 아닌 개념 예시입니다.

## 1. 대상 네트워크 구조

- 전산망 게이트웨이는 **HSRP**로 Active/Standby 이중화되어 하나의 가상 IP(VIP)로 서비스
- **OSPF** 영역으로 구간을 분리: 강의실망(Area 2) → 코어(Area 0) → 전산망(Area 1)
- 게이트웨이 뒤에 메일·DB·백업 등 서버 구역이 위치

![대학 네트워크 논리 토폴로지](../images/network_topology.png)

## 2. 트래픽이 제어 평면에 도달한 경로

라우터는 트래픽을 두 경로로 처리합니다. 단순 통과 트래픽은 **데이터 평면**(하드웨어/고속 경로)에서, 라우터 자신이 처리해야 하는 트래픽(라우팅 프로토콜, 관리 접속, 자신이 목적지인 패킷 등)은 **제어 평면**(CPU)에서 처리합니다.

SCN-03에서는 다음 조건이 겹치며 대량 트래픽이 제어 평면 자원을 소모했습니다.

1. 감염된 강의실 PC들이 라우팅 경로를 따라 게이트웨이 방향으로 대량 UDP를 전송
2. 이를 막는 **인터페이스 ACL이 없어** 트래픽이 게이트웨이까지 그대로 도달
3. 제어 평면 유입 트래픽을 제한하는 **CoPP가 없어** 라우터 CPU가 처리 부담을 그대로 떠안음
4. 결과적으로 **HSRP Hello 처리 지연 → 페일오버 불안정**, 게이트웨이 뒤 서버 구간 **ping 손실**로 가용성 침해 확인

## 3. 네트워크 계층 미비점 (발견 취약점)

| 미비점 | 주정통 | 네트워크 관점의 문제 |
|---|---|---|
| 인터페이스·VTY ACL 부재 | N-06 | 내부 어느 호스트에서든 게이트웨이로 임의의 대량 UDP가 허용됨 (출발지·포트 통제 없음) |
| CoPP(Control Plane Policing) 미적용 | N-23 | 제어 평면으로 유입되는 트래픽에 rate-limit이 없어 CPU 포화·HSRP 플래핑 위험 |
| uRPF 미적용 | — | 출발지 IP 검증이 없어 스푸핑·확산이 쉬움 |

## 4. 네트워크 하드닝 (방어 설계)

> 아래는 KISA 주정통 기준(N-06, N-23)에 맞춘 **방어용 개념 예시**입니다. 실제 대역·VIP·포트는 환경에 맞게 채워야 합니다.

### 4-1. 인터페이스 ACL — 비정상 UDP 차단 (N-06)

업무에 필요한 트래픽만 허용하고, 게이트웨이 VIP를 향한 비정상 대량 UDP는 차단합니다.

```
ip access-list extended GUARD-IN
 remark --- 업무상 필요한 UDP만 허용 ---
 permit udp <업무 대역> host <게이트웨이 VIP> eq <필요 포트>
 remark --- 게이트웨이 향 그 외 UDP 차단 ---
 deny   udp any host <게이트웨이 VIP> log
 permit ip  any any

interface <강의실 GW 인터페이스>
 ip access-group GUARD-IN in
```

### 4-2. CoPP — 제어 평면 rate-limit (N-23)

제어 평면으로 올라오는 트래픽에 상한을 둬, 대량 유입 시에도 라우팅·관리 기능이 유지되도록 합니다.

```
ip access-list extended CP-UDP-ACL
 permit udp any any

class-map match-any CP-UDP
 match access-group name CP-UDP-ACL

policy-map COPP
 class CP-UDP
  police <rate> conform-action transmit exceed-action drop

control-plane
 service-policy input COPP
```

### 4-3. uRPF · HSRP 보호

```
! 출발지 검증 (스푸핑 차단)
interface <내부 인터페이스>
 ip verify unicast source reachable-via rx

! HSRP 인증 및 안정화
interface <게이트웨이 인터페이스>
 standby <group> authentication md5 key-chain <chain>
 standby <group> preempt delay minimum 60
```

## 5. 재검증 기준과 현재 상태

보완 적용 전·후 동일한 조건에서 아래 지표를 비교해 방어 효과를 확인합니다.

| 지표 | 확인 방법 |
|---|---|
| 라우터 CPU | `show processes cpu` 제어 평면 부하 비교 |
| HSRP 안정성 | `show standby` 상태·Hello 지연, 페일오버 발생 여부 |
| 관리 응답성 | VTY 세션 응답 시간 |
| 서비스 영향 | 게이트웨이 뒤 서버 ping 손실률 |

> **현재 상태**: 1차 공격으로 ACL·CoPP 미비점을 확인하고 보완 설계까지 도출했으나, **보완 적용 후 재공격(재검증)은 보류** 상태입니다. 이는 다음 과제로 남았습니다.

## 6. 정리

SCN-03은 "공격이 성공했다"에서 끝나지 않고, **네트워크 계층에서 제어 평면을 어떻게 보호하는가**(ACL로 유입 차단 → CoPP로 제어 평면 보호 → uRPF로 출발지 검증 → HSRP 안정화)라는 방어 설계로 이어졌습니다. 공격자 관점에서 찾은 경로를 네트워크 하드닝으로 되돌려 정리한 기록입니다.
