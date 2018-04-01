rem linha para cria pasta de repositorio a ser compartilhada pelo webserver 
md webserver

rem linha para acessar a pasta repositorio webserver
cd webserver

rem linha com instrucao em python para executar o servidor web implementado na biblioteca CGIHTTPRequestHandler encontrado no arquivo
rem server.py na pasta http dentro da pasta de instação do python
rem servidor http configurado para porta 80
python -m http.server 80
