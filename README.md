# webserver

webserver em python para Windows 10.

1 - Para executar o servidor web é necessário ter a instalação do python 3.6 em seu computador.

2 - Adicione os seguintes caminhos dentro das variáveis do ambiente do Windows.
  Para acessar as variáveis do ambiente Windows vá até Paniel de controle / Sistemas /  configurações avançadas de sistema vá
  até a aba Avançado e clique em Variáveis de Ambiente, na grade Variáveis de Ambiente encontre a linha Path, clique em editar,
  vá no botão novo e adicione a seguinte linha:
  
  obs: troque o caminho em parenteses pelo caminho da pasta de instação do python em seu computador.
  
  C:\(instalação_python)\Lib\http
  clique em novo e adicione a nova linha também:
  C:\(instalação_python)\Lib
  mais uma nova linha:
  C:\(instalação_python)\
  e a ultima linha:
  C:\(instalação_python)\Scripts

3 - Apos adicionar as linhas do caminho do python dentro do windows agora copie o arquivo servidor.bat para o diretorio raiz "C:\"
e execute o arquivo servidor.bat. O arquivo servidor.bat ira criar uma pasta chamada webserver, essa pasta será o repositorio de arquivos do servidor web (c:\webserver).  Agora seu servidor web simples já está ativo.

4 - Copie os arquivos da pagina web para dentro da pasta c:\webserver, o arquivo index.html será automaticamente carregado pelo servidor quando requisitado por um cliente(navegador web), caso não tenha o arquivo index.html será exibido a listagem com os arquivo existente na pasta.
