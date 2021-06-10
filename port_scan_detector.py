import sys
import threading
import time
import socket
import struct
import json
import sched
import argparse
import hyperloglog
from statsmodels.tsa.holtwinters import ExponentialSmoothing


#Semaforo da acquisire per l'accesso al dizionario degli hosts contattai
sem = threading.Semaphore()
predizione=sys.maxsize
allowed_ports = [
    138,    # NetBIOS
    5353,   # Multicast DNS
    57621   # Spotify
]


def ip2int(addr: str):
    """
    Converte un indirizzo IPv4 da notazione puntata a numero decimale
    :param addr: indirizzo da convertire
    :return: l'intero corrispondente a 32 bit in numero decimale
    """
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def isMulticast(addr: str):
    """
    Controlla se l'indirizzo è di multicast (da 224.0.0.0 a 239.255.255.255) o 0.0.0.0
    :param addr: indirizzo da controllare in notazione puntata
    :return: True se è un indirizzo di multicast, False altrimenti
    """
    intaddr = ip2int(addr)
    if addr == "0.0.0.0" or (3758096384 <= intaddr <= 4026531839):
        return True
    else:
        return False


def tcp_scan_detect(flow):
    # TCP FLAGS
    # 2 -> SYN Scan (-sS, SYN bit set)
    # 22 -> RST Scan (-sT, kill connection)
    # 1 -> FIN Scan (-sF, FIN bit set)
    # 0 -> NULL Scan (-sN, No bites set)
    # 41 -> Xmas Scan (-sX, FIN, PSH, and URG)
    if int(flow["TCP_FLAGS"]) == 2 or int(flow["TCP_FLAGS"]) == 0 or \
             int(flow["TCP_FLAGS"]) == 22 or int(flow["TCP_FLAGS"]) == 1 \
             or int(flow["TCP_FLAGS"]) == 41:
        return True
    else:
        return False


def udp_scan_detect(flow, contacted):
    global predizione
    sem.acquire()
    if flow['IPV4_SRC_ADDR'] not in contacted:
        contacted[flow['IPV4_SRC_ADDR']] = hyperloglog.HyperLogLog(0.1)
    contacted[flow['IPV4_SRC_ADDR']].add(str(flow['IPV4_DST_ADDR']) + ':' + str(flow["L4_DST_PORT"]))
    sem.release()
    if len(contacted[flow['IPV4_SRC_ADDR']]) > (predizione*1.75):
        return True
    else:
        return False


def scan_detect(flow, contacted):
    """
    Metodo "gateway" per individuare gli scan.
    A seconda del protocollo utilizzato viene invocato il metodo corrispondende (se gli indirizzi coinvolti non
    sono mulicast e la porta non è tra quelle che ho visto essere usata comunemente per servizi dei quali spesso non
    si riceve risposta)
    :param flow: flusso in esame
    :param contacted: dizionario indicizzato per host contenente HLL della coppia host/porta (solo per pacchetti UDP)
    """
    if not isMulticast(flow['IPV4_SRC_ADDR']) and not isMulticast(flow['IPV4_DST_ADDR']) and flow["L4_DST_PORT"] not in allowed_ports :
        if int(flow['PROTOCOL']) == 6 and tcp_scan_detect(flow):
            print('Probabile scan TCP: ' + str(flow['IPV4_SRC_ADDR']) + ' scanner, ' + str(flow["IN_PKTS"]) + ' pkts, ' + str(flow["TCP_FLAGS"])
                  + ' flags, ' + str(flow['IPV4_DST_ADDR']) + ':' + str(
                flow["L4_DST_PORT"]) + ' bersaglio')
        if int(flow['PROTOCOL']) == 17 and udp_scan_detect(flow, contacted):
            print('Possibile scan UDP: ' + str(flow['IPV4_SRC_ADDR']) + ' scanner, ' + str(flow["IN_PKTS"]) + ' pkts, ' + str(flow['IPV4_DST_ADDR']) + ':' + str(
                flow["L4_DST_PORT"]) + ' bersaglio')


def des_predizione(sc, medie, contattati, interval):
    """
    Metodo che calcola il numero medio di hosts contattati e aggiorna la predizione del double exponential smoothing
    (se presenti sufficienti dati)
    :param sc: scheduler per chiamare il task al termine della sua esecuzione dopo interval secondi
    :param medie: lista di medie di host/porta contattati
    :param contattati: dizionario indiciazzo con gli hosts sorgente contenente degli hyperloglog con le coppie host/porta
    :param interval: intervallo di secondi dopo il quale eseguire nuovamete l'aggiornamento della predizione del DES
    :return:
    """
    tot = 0
    sem.acquire()
    for couples in contattati.values():
        tot+=len(couples)
    if tot > 0:
        if len(medie) >= 10:
            medie = medie[1:]
            if len(contattati) != 0:
                medie.append(tot / len(contattati))
            model = ExponentialSmoothing(medie, initialization_method='estimated')
            model_fit = model.fit(0.3, 0.7)
            global predizione
            predizione = model_fit.predict()[0]
            print('UDP prediction '+ str(model_fit.predict()[0]))
            #print(medie)
        else:
            if len(contattati)!=0:
                medie.append(tot / len(contattati))
            print("Dati UDP insufficienti (ancora" + str(10-len(medie)) + ')')
        #print(medie)
    sem.release()
    scheduler.enter(interval, 1, des_predizione, (sc, medie, contattati, interval))

def des_daemon(medie, contacted, interval):
    scheduler.enter(interval, 1, des_predizione, (scheduler, medie, contacted, interval))
    scheduler.run()


def erase(sc, medie, contacted, interval):
    sem.acquire()
    contacted.clear()
    #del medie[:]
    sem.release()
    scheduler.enter(interval, 1, erase, (sc, medie, contacted, interval))


def eraser_deamon(medie, contacted, interval):
    scheduler.enter(interval, 1, erase, (scheduler, medie, contacted, interval))
    scheduler.run()


if __name__ == '__main__':
    DEBUG = True
    scheduler = sched.scheduler(time.time, time.sleep)

    #Args parsing
    parser = argparse.ArgumentParser(description='Programma per individuare gli host che stanno effettuando port scanning.')
    parser.add_argument('-a', '--address', type=str, metavar='address', help='Indirizzo sul quale aprire il socket TCP', action='store',
                        default='127.0.0.1')
    parser.add_argument('-p', '--port', type=int, dest='port', action='store', metavar="port",
                        help='Porta sulla quale ricevere i flussi sotto forma di JSON tramite TCP',
                        default=2055)
    parser.add_argument('-d', '--des', type=int, dest='des_interval', action='store', metavar="seconds",
                        help='Secondi tra due calcoli del double exponential smoothing sulle coppie host/porta contattate tramite UDP',
                        default=10)
    parser.add_argument('-e', '--erase', type=int, dest='erase_interval', action='store', metavar="seconds",
                        help='Secondi tra due reset del numero delle coppie host/porta contattate tramite UDP',
                        default=180)
    parser.add_argument('--version', action='version', version='Port_Scanner_Detector 0.1')
    args = parser.parse_args()
    parser.print_help()
    #--------------------------------------

    #Inizializzazione oggetti

    #Dizionario dei contattati UDP
    contattati = dict()

    #Lista delle medie
    medie = list()

    #Threads daemon che eseguono i task schedulati
    des = threading.Thread(target=des_daemon, daemon=True, args=(medie, contattati, args.des_interval))
    eraser = threading.Thread(target=eraser_deamon, daemon=True, args=(medie, contattati, args.erase_interval))
    #Buffer temporaneo per immagazzinare il JSON parziale ottenuto dal payload frammentato
    tmp = ''

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((args.address, args.port))
        s.listen()
        while True:
            print("In attesa di connessioni")
            conn, addr = s.accept()
            with conn:
                print('Connesso a ', addr)
                if not (des.is_alive() and eraser.is_alive()):
                    des.start()
                    eraser.start()
                while True:
                    try:
                        conn.send(b'0')
                        data = conn.recv(2048)
                    except ConnectionResetError:
                        #TODO kill daemons after connection reset
                        print('Connessione con ' + str(addr) + ' interrotta')
                        break
                    if data is None:
                        continue
                    # Concatenazione del flusso per accorpare JSON spezzati dalla segmentazione in più segmenti TCP
                    tmp = tmp + data.decode('utf-8')
                    while tmp:
                        # Partiziono la stringa in 3 sottostringhe (prima del Carriage Return, CR e dopo il CR)
                        partizioni = tmp.partition('\n')
                        #Se il simbolo separatore è nullo (non presente)
                        if not partizioni[1]:
                            #Salvo in tmp il JSON incompleto
                            tmp = partizioni[0]
                            break
                        else:
                            try:
                                flow = json.loads(partizioni[0])
                                #print(flow)
                            except json.decoder.JSONDecodeError:
                                print("Formato JSON dei dati non riconosciuto", file=sys.stderr)
                                #conn.close()
                                break
                            try:
                                scan_detect(flow, contattati)
                            except KeyError:
                                print("Il template NetFlow utilizzato non ha tutti i campi richiesti", file=sys.stderr)
                            tmp = partizioni[2]
