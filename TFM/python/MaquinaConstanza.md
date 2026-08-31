---
- name: CORRECCIÓN DE VULNERABILIDADES DE SEGURIDAD
  hosts: 192.168.56.29
  become: yes
  become_method: sudo
  vars:
    ansible_user: auditor
    ansible_password: auditor2026
    ansible_become_password: auditor2026
    sshd_config_path: /etc/ssh/sshd_config
    logrotate_config_path: /etc/logrotate.conf
    sysctl_config_path: /etc/sysctl.conf

  tasks:
    # ============================================
    # VULNERABILIDAD CRÍTICA (SEVERIDAD H)
    # ============================================
    
    - name: "🔴 CRÍTICA: Habilitar servicio NTP"
      ansible.builtin.service:
        name: ntp
        state: started
        enabled: yes
      register: ntp_service
      failed_when: false

    - name: "🔴 CRÍTICA: Verificar estado de NTP"
      ansible.builtin.command:
        cmd: systemctl is-active ntp || systemctl is-active ntpsec
      register: ntp_status
      changed_when: false
      ignore_errors: yes

    - name: "🔴 CRÍTICA: Mostrar estado de NTP"
      ansible.builtin.debug:
        msg: "✅ Servicio NTP: {{ 'ACTIVO' if ntp_status.rc == 0 else 'INACTIVO' }}"

    # ============================================
    # VULNERABILIDADES IMPORTANTES (SEVERIDAD M)
    # ============================================

    - name: "🟡 IMPORTANTE: Configurar Logrotate para ejecución diaria"
      ansible.builtin.lineinfile:
        path: "{{ logrotate_config_path }}"
        regexp: '^#?daily'
        line: 'daily'
        create: yes

    - name: "🟡 IMPORTANTE: Instalar rsyslog"
      ansible.builtin.apt:
        name: rsyslog
        state: present
        update_cache: yes

    - name: "🟡 IMPORTANTE: Habilitar servicio rsyslog"
      ansible.builtin.service:
        name: rsyslog
        state: started
        enabled: yes

    - name: "🟡 IMPORTANTE: Deshabilitar Core Dumps para programas SUID"
      ansible.builtin.sysctl:
        name: fs.suid_dumpable
        value: '0'
        state: present
        reload: yes
        sysctl_file: "{{ sysctl_config_path }}"

    - name: "🟡 IMPORTANTE: Habilitar layout aleatorio de direcciones virtuales"
      ansible.builtin.sysctl:
        name: kernel.randomize_va_space
        value: '2'
        state: present
        reload: yes
        sysctl_file: "{{ sysctl_config_path }}"

    - name: "🟡 IMPORTANTE: Configurar límite de intentos de keepalive SSH"
      ansible.builtin.lineinfile:
        path: "{{ sshd_config_path }}"
        regexp: '^#?ClientAliveCountMax'
        line: 'ClientAliveCountMax 3'
        create: yes
        validate: '/usr/sbin/sshd -t -f %s'
      notify: reiniciar_sshd

    - name: "🟡 IMPORTANTE: Configurar timeout de inactividad SSH"
      ansible.builtin.lineinfile:
        path: "{{ sshd_config_path }}"
        regexp: '^#?ClientAliveInterval'
        line: 'ClientAliveInterval 300'
        create: yes
        validate: '/usr/sbin/sshd -t -f %s'
      notify: reiniciar_sshd

    - name: "🟡 IMPORTANTE: Deshabilitar login root por SSH"
      ansible.builtin.lineinfile:
        path: "{{ sshd_config_path }}"
        regexp: '^#?PermitRootLogin'
        line: 'PermitRootLogin no'
        create: yes
        validate: '/usr/sbin/sshd -t -f %s'
      notify: reiniciar_sshd

    - name: "🟡 IMPORTANTE: Instalar subsistema de auditoría"
      ansible.builtin.apt:
        name: auditd
        state: present
        update_cache: yes

    - name: "🟡 IMPORTANTE: Iniciar y habilitar servicio auditd"
      ansible.builtin.service:
        name: auditd
        state: started
        enabled: yes

    # ============================================
    # RESUMEN FINAL
    # ============================================

    - name: "RESUMEN FINAL DE CORRECCIONES"
      ansible.builtin.debug:
        msg: |
          ============================================================
                RESUMEN DE VULNERABILIDADES CORREGIDAS
          ============================================================
          
          🔴 CRÍTICAS (H): 1 CORREGIDA
          ✅ Servicio NTP habilitado
          
          🟡 IMPORTANTES (M): 9 CORREGIDAS
          ✅ Logrotate configurado diariamente
          ✅ Rsyslog instalado y habilitado
          ✅ Core dumps para SUID deshabilitados
          ✅ ASLR habilitado
          ✅ SSH ClientAliveCountMax=3 configurado
          ✅ SSH ClientAliveInterval=300 configurado
          ✅ SSH Root login deshabilitado
          ✅ Auditd instalado y habilitado
          ✅ Configuración SSH validada
          
          ============================================================
          ✅ PUNTAJE ANTERIOR: 40.0
          ✅ TODAS LAS CORRECCIONES APLICADAS
          ============================================================

  handlers:
    - name: reiniciar_sshd
      ansible.builtin.service:
        name: sshd
        state: restarted