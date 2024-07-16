#!/bin/bash

#
#	Programa para scans internos por meio da API do serviço HostedScan de forma automatizada.
#	versão beta 2.5.0
#		Novidades!
#			+	Adicionado visualização de versionamento.
#
#			+	Adicionado logo em ASCII.
#
#			+	Adicionado Verificações de comandos, variáveis e arquivos.
#
#			+	Adicionado Sistema de Chaves.
#
#			+	Adicionado interação com usuário ao longo do serviço.
#
#			+	Adicionado Scan OWASP ZAP automaticamente.
#

#	Chaves do Programa & Valores.
MENSAGEMAJUDA="
	Uso: bash HostedInternal.sh -k VALOR_API -t FAIXA_SUBREDE

	PARAMETROS:		DESCRIÇÃO:
	-h, --help		Mostra a tela de ajuda.
	-k, --key		Recebe valor da chave de api do HostedScan.
	-t, --target		Recebe a faixa de sub-rede para testes internos.
	-tU, --targerUDP	Receve a faixa de sub-rede para testes internos em UDP.
	-v, --version		Mostra a versão atual do programa.
	-oR, --owaspzap-report	Recebe report do owaspzap.
	-oW, --owaspzap		Recebe url para teste na ferramenta owaspzap.
	-oV, --openvas		Recebe report do openVAS.

"
NMAPTCP=0		#	Habilita scan tcp no nmap.
NMAPUDP=0		#	Habilita scan udp no nmap.
OWASPZAP=0		#	Habilita scan owasp zap.
OWASPZAPREPORT=0	#	Habilita leitura report OWASPZAP.
OPENVAS=0		#	Habilita leitura report OPENVAS.

#	Arte feita em ASCII
[ -f logoART.txt ] || echo "arte logo não encontrada..."
[ -f logoART.txt ] && cat logoART.txt

#	Inicio do loop que recebe as opções com o shift.
while test -n "$1"
do

#	Verifica opção escolhida.
case "$1" in

	-h | --help) 	#	Mostra mensagem de ajuda.
		echo "$MENSAGEMAJUDA"
		exit
	;;

	-k | --key)	#	Recebe valor da chave.
		APIKEY=$2
	;;

	-t | --target)	#	Recebe valor de subrede.
		NMAPTCP=1
		SUBREDE=$2
	;;

	-tU | --targetUDP)
		NMAPUDP=1
	;;

	-v | --version)		#	Mostra versão atual do programa.
		echo "HostedInternal.sh versão 2.0.0"
		exit
	;;

	-oR | --owaspzap-report)	#	Recebe report do owaspzap.
		OWASPZAPREPORT=1
		OWASPZAPFILE=$2
	;;

	-oW | --owaspzap)	#	Realiza scan owaspzap.
		OWASPZAP=1
		TARGET_URL=$2
	;;

	-oV | --openvas)	#	Recebe report do openvas.
		OPENVAS=1
		OPENVASFILE=$2
	;;

	esac
shift
done

#	Criando Pasta de alvos para o HostedScan e armazenando valores recebidos.
echo -e "\033[34m[*] Lendo chave da API ... \033[m"
if [ -z "$APIKEY" ]; then	#	Verificando valor de $APIKEY...
	echo -e "\033[31m[!] Erro! o usuário não informou o valor da chave API... \033[m"
	exit	#	Valor vazio, fechando...
fi

curl -s -H "Content-Type: application/json" -H "X-HOSTEDSCAN-API-KEY: $APIKEY" --request POST --data '{"source_type":"IMPORTED", "name":"INTERNAL_SCAN"}' https://api.hostedscan.com/v1/sources > TEMPDATAID.txt
IDVALUE=$(cat TEMPDATAID.txt | sed 's/"//g' | grep -oE '{id:([^,]+)' | sed 's/id://')	#	Guardando valor do id...

#	Executando NMAP extraindo resultados e enviando ao HOSTEDSCAN.
if [ "$NMAPTCP" -eq 1 ]; then		#	Verificando valor da chave para executar nmap...
	[ -z "$SUBREDE" ] && {		#	Verificando valor da variavel para executar nnmap...
		echo -e "\033[31m[!] Erro! o usuário não informou valores para scan nmap... \033[m"
		exit			#	Valor vazio saindo...
	}

	echo -e "\033[34m[*] Realizando scan NMAP em portas TCP e enviando ao HOSTEDSCAN... \033[m"
	nmap -v -oX HostedInternal.xml $SUBREDE		#	Nmap scan tcp e saida xml
	curl -s -H "X-HOSTEDSCAN-API-KEY: $APIKEY" -F scan_type=NMAP -F source_id=$IDVALUE -F file=@HostedInternal.xml https://api.hostedscan.com/v1/results
	echo -e "\033[36;1m[+] Scan NMAP em portas TCP enviado com sucesso! \033[m"

fi

#	Executando Owasp Zap extraindo resultados e enviando ao HOSTEDSCAN.
if [ "$OWASPZAP" -eq 1 ]; then
	# Caminho para o executável do ZAP
	#ZAP_PATH=

	# URL alvo
	echo -e "\033[34m[*]Iniciando scan em: $TARGET_URL\033[m"

	# Inicia o ZAP em modo daemon na porta 8080
	#$ZAP_PATH/zap.sh -daemon -port 8080 -config api.disablekey=true

	# Aguarda o ZAP iniciar completamente
	#sleep 10

	# Inicia spider scan para posteriormente iniciar active scan
	echo -e "\033[34m[*]Iniciando spider scan em: $TARGET_URL\033[m"
	curl -s -G "http://localhost:8080/JSON/spider/action/scan/" --data-urlencode "url=$TARGET_URL" --data-urlencode "maxchildren=10" --data-urlencode "recurse=true"
	sleep 5

	# Espera scan concluir...
	SPIDERSCANID=0

	while [ "$SPIDERSCANID" -ne "100" ]
	do
	curl -s -G "http://localhost:8080/JSON/spider/view/status/" --data-urlencode "scanId=0" > TEMPSCANID.txt
	SPIDERSCANID=$(cat TEMPSCANID.txt | sed 's/"//g' | grep -oE '{status:([^,]+)'|sed 's/}//' | sed 's/status://')
	echo -e "\n\033[34m[*]o status do spider scan: $SPIDERSCANID%\033[m"
	done

	# Inica scan ativo
	echo -e "\033[34m[*]Iniciando scan ativo em: $TARGET_URL\033[m"
	curl -s -G "http://localhost:8080/JSON/ascan/action/scan/" \
	--data-urlencode "url=$TARGET_URL" \
	--data-urlencode "recurse=true" \
	--data-urlencode "inScopeOnly=false" \
	--data-urlencode "scanPolicyName=Default Policy" \
	--data-urlencode "method=GET" \
	--data-urlencode "postdata=""" \
	--data-urlencode "contextId="

	# Espera scan concluir...
	ACTIVESCANID=0

	while [ "$ACTIVESCANID" -ne "100" ]
	do
	curl -s -G "http://localhost:8080/JSON/ascan/view/status/" --data-urlencode "scanId=0" > TEMPSCANID2.txt
	ACTIVESCANID=$(cat TEMPSCANID2.txt | sed 's/"//g' | grep -oE '{status:([^,]+)'|sed 's/}//' | sed 's/status://')
	echo -e "\n\033[34m[*]o status do active scan: $ACTIVESCANID%\033[m"
	done

	# Gerar Report
	TITLEREPORT="DEFAULTTITLE"
	FILENAME="JSONHOSTEDINTERNALREPORT"
	curl -s -G "http://localhost:8080/JSON/reports/action/generate/" \
	--data-urlencode "title=$TITLEREPORT" \
	--data-urlencode "template=traditional-json" \
	--data-urlencode "sites=$TARGET_URL" \
	--data-urlencode "reportFileName=$FILENAME"

	# Enviando Report
	curl -s -H "X-HOSTEDSCAN-API-KEY: $APIKEY" -F "scan_type=OWASP_ZAP" -F "source_id=$IDVALUE" -F "target=$TARGET_URL" -F "file=@$FILENAME.json" https://api.hostedscan.com/v1/results
	echo -e "\nOwasp zap concluido..."

fi

#	Envia report já feito no OwaspZap para HostedScan.
if [ "$OWASPZAPREPORT" -eq 1 ]; then		#	Verificando valor da chave para enviar report OWASPZAP...
	TESTJSON=$(file "$OWASPZAPFILE" | grep "json")		#	Verificando extensão de arquivo para enviar report OWASPZAP...
		[ -z "$TESTJSON" ] && {
			echo -e "\033[31m[!] Erro! Extensão inválida para arquivo de report OWASPZAP... \033[m"
			exit
		}

	echo -e "\033[34m[*] Lendo arquivo JSON Report OWASP ZAP e enviando ao HOSTEDSCAN ... \033[m"
	curl -s -H "X-HOSTEDSCAN-API-KEY: $APIKEY" -F "scan_type=OWASP_ZAP" -F "source_id=$IDVALUE" -F "target=http://localhost/" -F "file=@$OWASPZAPFILE" https://api.hostedscan.com/v1/results
	echo -e "\033[36;1m[+] Report OWASPZAP enviado com sucesso! \033[m"

fi

#	Executando OpenVas extraindo reusultados e enviando ao HOSTEDSCAN.
#			Inserir comandos que geram XML report automaticamente...
if [ "$OPENVAS" -eq 1 ]; then		#	Verificando valor da chave para enviar report OPENVAS...
	TESTXML=$(file "$OPENVASFILE" | grep "xml")	#	Verficando extensão de arquivo para enviar report OPENVAS...
        	[ -z "$TESTXML" ] && {
                	echo -e "\033[31m[!] Erro! Extensão inválida para arquivo de report OpenVas... \033[m"
                	exit
		}

	echo -e "\033[34m[*] Lendo arquivo XML Report OPENVAS e enviando ao HOSTEDSCAN ... \033[m"
	curl -s -H "X-HOSTEDSCAN-API-KEY: $APIKEY" -F "scan_type=OPENVAS" -F "source_id=$IDVALUE" -F "file=@$OPENVASFILE" https://api.hostedscan.com/v1/results
	echo -e "\033[36;1m[+] Report OPENVAS enviado com sucesso! \033[m"

fi

#	Executando Nmap em UDP e enviando ao HOSTEDSCAN.
if [ "$NMAPUDP" -eq 1 ]; then		#	Verificando valor da chave para executar nmap...
	 [ -z "$SUBREDE" ] && {          #       Verificando valor da variavel para executar nmap...
                echo -e "\033[31m[!] Erro! o usuário não informou valores para scan nmap em UDP... \033[m"
                exit                    #       Valor vazio saindo...
        }

	echo -e "\033[34m[*] Realizando scan NMAP em portas UDP e enviando ao HOSTEDSCAN... \033[m"
	nmap -v -sU -oX HostedInternalUDP.xml $SUBREDE
	curl -s -H "X-HOSTEDSCAN-API-KEY: $APIKEY" -F scan_type=NMAP_UDP -F source_id=$IDVALUE -F file=@HostedInternalUDP.xml https://api.hostedscan.com/v1/results
	echo -e "\033[36;1m[+] Scan NMAP em portas UDP enviado com sucesso! \033[m"

fi
