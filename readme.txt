# webserver
webserver em python para Windows 10.


1 - Para executar o servidor web � necess�rio ter a instala��o do python 3.6 em seu computador.


2 - Adicione os seguintes caminhos dentro das vari�veis do ambiente do Windows.
  Para acessar as vari�veis do ambiente Windows v� at� 

Paniel de controle / Sistemas /  configura��es avan�adas de sistema v�
  at� a aba Avan�ado e clique em Vari�veis de Ambiente, na tela Vari�veis de Ambiente encontre 

a linha Path, clique em editar,
  v� no bot�o novo e adicione a seguinte linha:
  C:\Users\Daniel\AppData\Local\Programs\Python\Python36-32\Lib\http
  

clique em novo e adicione a nova linha tamb�m:
  C:\Users\Daniel\AppData\Local\Programs\Python\Python36-32\Lib
  

mais uma nova linha:
  C:\Users\Daniel\AppData\Local\Programs\Python\Python36-32\
  

e a ultima linha:
  C:\Users\Daniel\AppData\Local\Programs\Python\Python36-32\Scripts

3 - 

Apos adicionar as linhas do caminho do python dentro do windows agora copie o arquivo servido.bat para o diretorio raiz C:\
e execute o arquivo servidor.bat.

O arquivo servidor.bat ira criar uma pasta chamada webserver, essa pasta ser� o repositorio de arquivos do servidor web (c:\webserver).  

Agora seu servidor web simples j� est� ativo.

4 - Copie os arquivos do site dentro da pasta c:\webserver, o arquivo index.html ser� automaticamente 

carregado pelo servidor quando requisitado por um cliente(navegador web), caso n�o tenha o arquivo index.html ser� exibido a listagem com os arquivo existente na pasta.