import os
import json
from openai import OpenAI
#from dotenv import load_dotenv

# Inicializa el cliente de OpenAI (Asegúrate de exportar tu API KEY en la terminal: export OPENAI_API_KEY="tu-key")
client = OpenAI(api_key="llave")

# 1. Tu JSON de entrada (Reporte de vulnerabilidades)
reporte_json = {
 
}

# 2. Definición de los roles/prompts
system_prompt = (

'''Eres especialista en hardening Linux, Ansible y los benchmarks CIS (Center for Internet Security). Recibirás hallazgos OpenSCAP en JSON.
Genera SOLO un playbook Ansible YAML válido para remediar los fallos recibidos.
REGLAS:
-Usa módulos idempotentes; evita shell/command/raw.
-`hosts: all`, `become: true`.
-Procesa solo `failures`.
-No inventes valores ni remediaciones.
-Analiza id, title, desc, reason y fix conjuntamente.
-Paquetes: usa apt y verifica disponibilidad antes de instalar.
-Servicios: usa service/systemd.
-Archivos: usa lineinfile/blockinfile/template.
-Sysctl: usa ansible.posix.sysctl.
-SSH: modifica solo la directiva necesaria, valida antes de aplicar y usa reload, nunca restart.
-Nunca reinicies, cambies el puerto SSH, elimines usuarios, modifiques firewall ni detengas servicios críticos.
-No automatices particiones, LVM, filesystems ni migraciones de /home o /tmp.
-Si una remediación es insegura, ambigua o requiere un valor desconocido, omítela.
-Responde únicamente con YAML, sin comentarios ni explicaciones'''
)

user_content = f"Genera el playbook de hardening para este reporte de fallas:\n{json.dumps(reporte_json, indent=2)}"

try:
    # 3. Llamada a la API utilizando gpt-4o-mini
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ],
        temperature=0.2 # Temperatura baja para garantizar código preciso y estructurado
    )

    # 4. Extraer y mostrar el Playbook resultante
    playbook_generado = response.choices[0].message.content
    print("--- PLAYBOOK GENERADO CON ÉXITO ---")
    print(playbook_generado)

    print("\n--Uso de tokens--")
    print(f"Tokens de entrada: {response.usage.prompt_tokens}")
    print(f"Tokens de salida: {response.usage.completion_tokens}")
    print(f"Total Tokens: {response.usage.total_tokens}")

    cost_input = (response.usage.prompt_tokens / 1_000_000) * 0.15
    # 500 / 1_000_000 = 0.0005
    cost_output = (response.usage.completion_tokens / 1_000_000) * 0.60
    total_cost = cost_input + cost_output

    print(f"\nCosto estimado: ${total_cost:.6f} USD")

    print(f"\nID de la respuesta: {response.id}")
    print(f"Modelo usado: {response.model}")


    # Opcional: Guardar directamente en un archivo .yml
    with open("hardening_playbook.yml", "w", encoding="utf-8") as f:
        f.write(playbook_generado.replace("```yaml", "").replace("```", "").strip())

except Exception as e:
    print(f"Error al conectar con la API de OpenAI: {e}")
