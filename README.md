# Proyecto1CriptoEjecutable

El repositorio cuenta con un archivo ejecutable, un archivo en formato ipynb (para ejecutarse en jupyter notebook o en google colab) y un archivo .py, para ejecutarse directamente en terminal (python main.py).

En cualquiera de los casos, es importante colocar el archivo .xlsx en la misma carpeta donde se encuentra el archivo a ejecutar, ya que allí se cuenta con los vectores de prueba de los algoritmos. Además, es importante
mencionar que la ejecución no muestra ninguna salida hasta que aparecen las primeras imágenes de comparativa de los algoritmos de hash. Una vez que aparezca la primera imagen, las demás aparecerán conforme se vaya cerrando la imagen desplegada.
Después de las imágenes de hash, el programa volverá a su ejecución y tardará aproximadamente 15 segundos en mostrar los resultados de los algoritmos de cifrado y descifrado. Lo mismo ocurrirá para los algoritmos de firma. 


# OPCIÓN 1 (recomendada, ya que no requiere instalar bibliotecas):  ARCHIVO EJECUTABLE
  El ejecutable puede ejecutarse en Windows haciendo doble click sobre él o navegando a la carpeta en donde se encuentra desde una terminal (cmd o powershell) y ejecutando el comando start main.exe
  En linux, el ejecutable .exe se puede correr utilizando el comando wine main.exe (en caso de tener wine instalado). Si no se cuenta con wine en la distribución de linux, se puede instalar con el comando sudo apt-get wine64
  
# OPCIÓN 2: ARCHIVO .IPYNB
  En esta opción, se debe de abrir un cuaderno de Jupyter Notebook o Google Colab y cargar el archivo .ipynb. Una vez cargado, en caso de no contar con las bibliotecas especificadas en requirements.txt, se debe de 
  ejecutar las celdas que dicen pip install ... Posteriormente, se ejecutan las celdas en el orden en el que se encuentran.
  
 # OPCIÓN 3: ARCHIVO .PY
  En esta opción, se debe de contar con las bibliotecas instaladas en el directorio de ejecución de main.py. El archivo main.py se ejecuta con el comando python main.py. 
