package iphlpapi

/*
Для таблицы маршрутизации ожидаемый метод такой:
Сначала запросить 0.0.0.0/0, чтобы получить исходный маршрут по умолчанию,
затем добавить маршрут по умолчанию для VPN-сервера,
после этого при необходимости добавить маршруты VPN.
Для VPN-маршрута 0.0.0.0/0 можно попробовать меньший показатель метрики (metric), 
или можно разделить на два маршрута.
При переподключении можно удалить все не-линейные маршруты интерфейса VPN.
Формат таблицы маршрутизации:
Сеть назначения uint32, маска сети (бит) – младшие 6 бит байта,
шлюз VPN/по умолчанию – старший бит байта
*/


import (
	"fmt"
	"net"
	"unsafe"
)

// При добавлении маршрута с слишком низкой метрикой возвращается ошибка 106
const routeMetric = 93

type RouteRow struct {
	ForwardDest      [4]byte 
	ForwardMask      [4]byte 
	ForwardPolicy    uint32  
	ForwardNextHop   [4]byte 
	ForwardIfIndex   uint32  
	ForwardType      uint32  
	ForwardProto     uint32  
	ForwardAge       uint32  
	ForwardNextHopAS uint32  
	ForwardMetric1   uint32 
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

// ForwardType: 3 – локальный интерфейс, 4 – удалённый интерфейс
// ForwardProto: 3 – статический маршрут, 2 – локальный интерфейс, 5 – шлюз EGP
// ForwardMetric1 – метрика (количество прыжков), смысл зависит от ForwardProto

func (rr *RouteRow) GetForwardDest() net.IP {
	return net.IP(rr.ForwardDest[:])
}
func (rr *RouteRow) GetForwardMask() net.IP {
	return net.IP(rr.ForwardMask[:])
}
func (rr *RouteRow) GetForwardNextHop() net.IP {
	return net.IP(rr.ForwardNextHop[:])
}

func GetRoutes() ([]RouteRow, error) {
	buf := make([]byte, 4+unsafe.Sizeof(RouteRow{}))
	buf_len := uint32(len(buf))

	proc_GetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&buf_len)), 0)

	var r1 uintptr
	for i := 0; i < 5; i++ {
		buf = make([]byte, buf_len)
		r1, _, _ = proc_GetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&buf_len)), 0)
		if r1 == 122 {
			continue
		}
		break
	}

	if r1 != 0 {
		return nil, fmt.Errorf("Failed to get the routing table, return value：%v", r1)
	}

	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	routes := make([]RouteRow, num)
	sr := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(num)
	rowSize := unsafe.Sizeof(RouteRow{})

	if len(buf) < int((unsafe.Sizeof(num) + rowSize*uintptr(num))) {
		return nil, fmt.Errorf("System error: GetIpForwardTable returns the number is too long, beyond the buffer。")
	}

	for i := uint32(0); i < num; i++ {
		routes[i] = *((*RouteRow)(unsafe.Pointer(sr + (rowSize * uintptr(i)))))
	}

	return routes, nil
}
