# Example network of 2 worm holes and 14 nodes.


#set n0 [$ns node]
#$n0 random-motion 0
#$ns initial_node_pos $n0 30
Phy/WirelessPhy set CPThresh_ 10.0
Phy/WirelessPhy set CSThresh_ 9.21756e-11 ;#550m
Phy/WirelessPhy set RXThresh_ 4.4613e-10 ;#250m
Phy/WirelessPhy set bandwidth_ 512kb
Phy/WirelessPhy set Pt_ 8000.2818
Phy/WirelessPhy set freq_ 2.4e+9
Phy/WirelessPhy set L_ 1.0 
Antenna/OmniAntenna set X_ 0
Antenna/OmniAntenna set Y_ 0
Antenna/OmniAntenna set Z_ 0.25
Antenna/OmniAntenna set Gt_ 1
Antenna/OmniAntenna set Gr_ 1


set val(chan)   Channel/WirelessChannel    ;# channel type
set val(prop)   Propagation/TwoRayGround   ;# radio-propagation model
set val(netif)  Phy/WirelessPhy            ;# network interface type
set val(mac)    Mac/802_11                 ;# MAC type
set val(ifq)    Queue/DropTail/PriQueue    ;# interface queue type
set val(ll)     LL                         ;# link layer type
set val(ant)    Antenna/OmniAntenna        ;# antenna model
set val(ifqlen) 50                         ;# max packet in ifq
set val(nn)     16                        ;# number of mobilenodes
set val(rp)     AODV                       ;# routing protocol
set val(x)      1440                      ;# X dimension of topography
set val(y)      100                      ;# Y dimension of topography
set val(stop)   10.0                         ;# time of simulation end
#set val(wormholes) 1;
#===================================
#        Initialization        
#===================================
#Create a ns simulator
set ns [new Simulator]

#Setup topography object
set topo       [new Topography]
$topo load_flatgrid $val(x) $val(y)
create-god $val(nn)

#Open the NS trace file
set tracefile [open good.tr w]
$ns trace-all $tracefile

#Open the NAM trace file
set namfile [open out.nam w]
$ns namtrace-all $namfile
$ns namtrace-all-wireless $namfile $val(x) $val(y)
set chan [new $val(chan)];#Create wireless channel

#===================================
#     Mobile node parameter setup
#===================================
$ns node-config -adhocRouting  $val(rp) \
                -llType        $val(ll) \
                -macType       $val(mac) \
                -ifqType       $val(ifq) \
                -ifqLen        $val(ifqlen) \
                -antType       $val(ant) \
                -propType      $val(prop) \
                -phyType       $val(netif) \
                -channel       $chan \
                -topoInstance  $topo \
                -agentTrace    ON \
                -routerTrace   ON \
                -macTrace      ON \
                -movementTrace ON

#===================================
#        Nodes Definition        
#===================================
#Create 14 nodes
set n0 [$ns node]
$n0 set X_ 100
$n0 set Y_ 399
$n0 set Z_ 0.0
$ns initial_node_pos $n0 20

set n1 [$ns node]
$n1 set X_ 200
$n1 set Y_ 200
$n1 set Z_ 0.0
$ns initial_node_pos $n1 20
set n2 [$ns node]
$n2 set X_ 199
$n2 set Y_ 600
$n2 set Z_ 0.0
$ns initial_node_pos $n2 20
set n3 [$ns node]
$n3 set X_ 398
$n3 set Y_ 599
$n3 set Z_ 0.0
$ns initial_node_pos $n3 20

set n4 [$ns node]
$n4 set X_ 399
$n4 set Y_ 199
$n4 set Z_ 0.0
$ns initial_node_pos $n4 20
set n5 [$ns node]
$n5 set X_ 799
$n5 set Y_ 201
$n5 set Z_ 0.0
$ns initial_node_pos $n5 20
set n6 [$ns node]
$n6 set X_ 1000
$n6 set Y_ 201
$n6 set Z_ 0.0
$ns initial_node_pos $n6 20
set n7 [$ns node]
$n7 set X_ 1099
$n7 set Y_ 400
$n7 set Z_ 0.0
$ns initial_node_pos $n7 20
set n8 [$ns node]
$n8 set X_ 1000
$n8 set Y_ 598
$n8 set Z_ 0.0
$ns initial_node_pos $n8 20
set n9 [$ns node]
$n9 set X_ 800
$n9 set Y_ 599
$n9 set Z_ 0.0
$ns initial_node_pos $n9 20
set n10 [$ns node]
$n10 set X_ 1
$n10 set Y_ 200
$n10 set Z_ 0.0
$ns initial_node_pos $n10 20
set n11 [$ns node]
$n11 set X_ 1
$n11 set Y_ 600
$n11 set Z_ 0.0
$ns initial_node_pos $n11 20

set n12 [$ns node]
$n12 set X_ 299
$n12 set Y_ 400
$n12 set Z_ 0.0
$ns initial_node_pos $n12 20
$ns at 0.01 "$n12 label \"source node12\""

set n13 [$ns node]
$n13 set X_ 900
$n13 set Y_ 399
$n13 set Z_ 0.0
$ns initial_node_pos $n13 20
$ns at 0.01 "$n13 label \"destiantion node13\""


# configure Wormholes

		#puts "Making first wormhole"
	 	set n14 [$ns node]
		$n14 set X_ 300.0
		$n14 set Y_ 500.0
		$n14 set Z_ 0.0
		$ns initial_node_pos $n14 20	
		$ns at 0.01 "$n14 label \"wormhole1\""

		set n15 [$ns node]
		$n15 set X_ 900.0
		$n15 set Y_ 300.0
		$n15 set Z_ 0.0
		$ns initial_node_pos $n15 20
		$ns at 0.01 "$n15 label \"wormhole2\""

#[$n14 set ll_(0)] wormhole-peer [$n15 set ll_(0)]
#[$n15 set ll_(0)] wormhole-peer [$n14 set ll_(0)]
#===================================
#        Agents Definition        
#===================================
#Setup a UDP connection
set udp0 [new Agent/UDP]
$ns attach-agent $n12 $udp0
set null1 [new Agent/Null]
$ns attach-agent $n13 $null1
$ns connect $udp0 $null1
$udp0 set packetSize_ 1500

#===================================
#        Applications Definition        
#===================================
#Setup a CBR Application over UDP connection
set cbr0 [new Application/Traffic/CBR]
$cbr0 attach-agent $udp0
$cbr0 set packetSize_ 1000
$cbr0 set rate_ 1.0Mb
$cbr0 set random_ null
$ns at 0.0 "$cbr0 start"
$ns at 10.0 "$cbr0 stop"

#===================================
#        Termination        
#===================================
#Define a 'finish' procedure
proc finish {} {
    global ns tracefile namfile
    $ns flush-trace
    close $tracefile
    close $namfile
    exec nam out.nam &
    exit 0
}
for {set i 0} {$i < $val(nn) } { incr i } {
    $ns at $val(stop) "\$n$i address?"
    $ns at $val(stop) "\$n$i reset"
}
$ns at $val(stop) "$ns nam-end-wireless $val(stop)"
$ns at $val(stop) "finish"
$ns at $val(stop) "puts \"done\" ; $ns halt"
$ns run
