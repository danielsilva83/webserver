# servidor webserver em python

Instruções para executar o webserver em python para windows 10 32bits:

	1 – Realize a instalação do Python 3.6. (caso já tiver o python instalado no seu dispositivo pule esta etapa).
	2 – faça o download do arquivo "servidor.pyc" dentro do repositório do github https://github.com/danielsilva83/webserver
	3 – Copie o arquivo ‘servidor.pyc’ para dentro da pasta que contem a página web a ser exibida e atualize o path de instalação do python nas variáveis de ambientes no windows (caso não tenha marcado opção de atualizar path na instalação do python)
	4 – Execute o arquivo ‘servidor.pyc’ e após abra o navegador e digite o endereço ipv4 do computador na barra de endereço. Se a pasta em questão conter o arquivo index.html a página será exibida no navegador web, caso não tenha o arquivo index.html será exibida a listagem dos arquivos contidos na página, e em caso de arquivo inexistente será enviado erro 404 arquivo não encontrado.

Instruções para rodar  o código em python em diversos sistemas operacionais:

	0 – Realize a instalação do Python de acordo com o sistema operacional do seu dispositivo. (caso já tiver o python instalado no dispositivo  pule esta etapa).
	1 - é necessário fazer o download do arquivo ‘servidor.py’ que também se encontra no repositório github no link acima.
	1.1 - atualize o path de instalação do python nas variáveis de ambientes no windows  (caso não tenha marcado opção de atualizar path na instalação do python)
	2 - Abra o prompt de comando do windows.
	3 – vá até a pasta onde se encontra o arquivo ‘servidor.py’
	4 – digite o seguinte comando no prompt do windows (CMD) para compilar o programa, c:\pasta\>python servidor.py logo em seguida tecle enter.
