### tcp-block
- Out of path 환경에서 TCP flag(RST, FIN)를 이용하여 사이트 차단하는 프로그램을 작성하라.
- https://gitlab.com/gilgil/sns/-/wikis/tcp-block/report-tcp-block
- Out of path의 대표격인 pcap library를 이용하여 패킷을 수신한다.
- 수신된 패킷의 TCP Data 영역에 pattern이 검색되는 경우 차단 패킷을 양쪽으로 송신한다.
- 정방향(forward)은 RST flag를 포함한 패킷을 송신한다.
- 역방향(backward)는 FIN flag 및 "blocked!!!"라는 TCP Data를 포함한 패킷을 송신한다.

### Link
- tcp block
    - https://gitlab.com/gilgil/sns/-/wikis/tcp-block/tcp-block
    - https://www.youtube.com/watch?v=5EOKiAN749w&feature=youtu.be&ab_channel=GilbertLee
- ip header, tcp header
    - http://ktword.co.kr/abbr_view.php?m_temp1=1859
    - http://www.ktword.co.kr/abbr_view.php?nav=&m_temp1=1889&id=1103
    - http://www.ktword.co.kr/abbr_view.php?nav=&m_temp1=2437&id=1103
    - https://www.geeksforgeeks.org/calculation-of-tcp-checksum/
- port forwarding
    - https://hahaite.tistory.com/283


https://www.notion.so/antemrdm/TCP-Block-b2c1bdc26f0d40f586111dadaa61abc8