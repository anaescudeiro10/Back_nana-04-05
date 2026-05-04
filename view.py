import os
import threading
import jwt
import datetime
import random
from flask import jsonify, request, make_response, render_template
from main import app, get_db_connection
from funcao import (verificar_senha, criptografar, checar_senha,
                    enviando_email, gerar_token, remover_bearer, verificar_reuso_senha)

# Garante a pasta de fotos de perfil
caminho_perfis = os.path.join(app.config['UPLOAD_FOLDER'], "usuarios")
if not os.path.exists(caminho_perfis):
    os.makedirs(caminho_perfis)



@app.route('/criar_usuario', methods=['POST'])
def criar_usuario():
    con = get_db_connection()
    if not con:
        return jsonify({'erro': 'Erro de conexão com o banco'}), 500

    cur = con.cursor()

    try:
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        tipo = request.form.get('tipo', 'cliente')
        telefone = request.form.get('telefone')
        endereco = request.form.get('endereco')

        # Validações básicas
        if not nome or not email or not senha:
            return jsonify({'erro': 'Nome, Email e Senha são obrigatórios.'}), 400

        # Verifica se email já existe
        cur.execute("SELECT id_usuario FROM USUARIOS WHERE email = ?", (email,))
        if cur.fetchone():
            return jsonify({'erro': 'Este e-mail já está cadastrado.'}), 409

        # Criptografa senha
        senha_hash = criptografar(senha)

        # Insere usuário
        cur.execute("""
            INSERT INTO USUARIOS (nome, email, senha, tipo, conta_confirmada)
            VALUES (?, ?, ?, ?, FALSE)
            RETURNING id_usuario
        """, (nome, email, senha_hash, tipo))

        id_usuario = cur.fetchone()[0]

        print(f"[DEBUG] Usuário criado ID: {id_usuario}")

        # 🔥 SE FOR CLIENTE
        if tipo.lower() == 'cliente':

            # Insere cliente
            cur.execute("""
                INSERT INTO CLIENTES (id_usuario, nome, telefone, endereco)
                VALUES (?, ?, ?, ?)
            """, (id_usuario, nome, telefone, endereco))

            # Gera código
            codigo_random = f"{random.randint(0, 999999):06d}"
            print(f"[DEBUG] Código gerado: {codigo_random}")

            # Salva código
            cur.execute("""
                INSERT INTO CONFIRMAR_CODIGO (id_usuario, codigo)
                VALUES (?, ?)
            """, (id_usuario, codigo_random))

            # Commit ANTES do email
            con.commit()

            # Monta email
            assunto = "Confirme seu cadastro"
            corpo = f"Olá {nome}, seu código de ativação é: {codigo_random}"

            print("[DEBUG] Enviando email...")

            # 🚨 SEM THREAD (pra ver erro)
            enviando_email(email, assunto, corpo)

            print("[DEBUG] Email enviado (ou tentou enviar)")

            return jsonify({
                "mensagem": "Usuário criado! Verifique seu e-mail."
            }), 201

        # Se não for cliente
        con.commit()
        return jsonify({"mensagem": "Usuário criado com sucesso."}), 201

    except Exception as e:
        con.rollback()
        print(f"[ERRO] {e}")
        return jsonify({'erro': str(e)}), 500

    finally:
        cur.close()
        con.close()


@app.route('/login_usuario', methods=['POST'])
def login_usuario():
    con = get_db_connection()
    cur = con.cursor()
    dados = request.get_json(silent=True) or request.form
    email = dados.get('email')
    senha = dados.get('senha')

    try:
        cur.execute('SELECT id_usuario, senha, nome, tipo, conta_confirmada FROM USUARIOS WHERE email = ?', (email,))
        resultado = cur.fetchone()

        if not resultado:
            return jsonify({'erro': 'Usuário não encontrado'}), 404

        id_user, senha_banco, nome, tipo, confirmado = resultado

        if not confirmado:
            return jsonify({'erro': 'Conta pendente. Confirme seu e-mail.'}), 403

        if checar_senha(senha, senha_banco):
            token = gerar_token(email)
            resp = make_response(jsonify({
                'mensagem': f'Bem-vindo {nome}!',
                'token': token,
                'tipo': tipo,
                'id_usuario': id_user
            }), 200)
            resp.set_cookie('access_token', token, httponly=True, max_age=3600, samesite="Lax")
            return resp
        return jsonify({'erro': 'Senha incorreta.'}), 401
    finally:
        cur.close()
        con.close()


@app.route('/confirmar_codigo', methods=['POST'])
def confirmar_codigo():
    con = get_db_connection()
    if not con:
        return jsonify({'erro': 'Erro de conexão'}), 500
    cur = con.cursor()
    try:
        # Recebendo via JSON ou Form para garantir compatibilidade
        dados = request.get_json(silent=True) or request.form
        email = dados.get('email')
        codigo = dados.get('codigo')

        if not email or not codigo:
            return jsonify({'erro': 'E-mail e código são obrigatórios.'}), 400

        cur.execute(""" 
            SELECT c.id_confirmacao, c.id_usuario  
           FROM CONFIRMAR_CODIGO c 
            JOIN USUARIOS u ON c.id_usuario = u.id_usuario 
            WHERE u.email = ? AND c.codigo = ? AND c.utilizado = FALSE 
            ORDER BY c.data_geracao DESC 
        """, (email, codigo))

        res = cur.fetchone()

        if not res:
            return jsonify({'erro': 'Código inválido, já utilizado ou e-mail incorreto.'}), 400

        id_conf, id_user = res

        # 1. Ativa a conta do usuário
        cur.execute("UPDATE USUARIOS SET conta_confirmada = TRUE WHERE id_usuario = ?", (id_user,))
        # 2. Marca o código como utilizado
        cur.execute("UPDATE CONFIRMAR_CODIGO SET utilizado = TRUE WHERE id_confirmacao = ?", (id_conf,))

        con.commit()
        return jsonify({'mensagem': 'Conta ativada com sucesso! Agora você pode fazer login.'}), 200

    except Exception as e:
        con.rollback()
        return jsonify({'erro': f'Erro ao confirmar: {str(e)}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/excluir_usuario/<int:id_usuario>', methods=['DELETE'])
def excluir_usuario(id_usuario):
    con = get_db_connection()
    cur = con.cursor()
    try:
        cur.execute("DELETE FROM CLIENTES WHERE ID_USUARIO = ?", (id_usuario,))
        cur.execute("DELETE FROM USUARIOS WHERE id_usuario = ?", (id_usuario,))
        con.commit()
        return jsonify({'mensagem': 'Usuário excluído.'}), 200
    except Exception as e:
        con.rollback()
        return jsonify({'erro': str(e)}), 500
    finally:
        cur.close()
        con.close()


@app.route('/editar_usuario/<int:id_usuario>', methods=['PUT', 'POST'])
def editar_usuario(id_usuario):
    con = get_db_connection()
    cur = con.cursor()
    try:
        # 1. Busca dados atuais do usuário
        cur.execute("SELECT nome, email, senha FROM USUARIOS WHERE id_usuario = ?", (id_usuario,))
        user_data = cur.fetchone()

        if not user_data:
            return jsonify({'erro': 'Usuário não encontrado'}), 404

        nome_atual, email_atual, senha_hash_atual = user_data

        nome = request.form.get('nome') or nome_atual
        email = request.form.get('email') or email_atual
        senha_nova = request.form.get('senha')
        foto = request.files.get('foto')

        senha_final = senha_hash_atual  # Padrão é manter a senha atual

        # 2. Lógica de Validação de Senha (se o usuário preencheu o campo senha)
        if senha_nova and senha_nova.strip() != "":

            erro_forca = verificar_senha(senha_nova)
            if erro_forca:
                return jsonify({'erro': erro_forca}), 400

            if checar_senha(senha_nova, senha_hash_atual):
                return jsonify({'erro': 'A nova senha não pode ser igual à senha atual.'}), 400

            if verificar_reuso_senha(id_usuario, senha_nova, cur):
                return jsonify({'erro': 'Esta senha já foi utilizada recentemente. Escolha outra.'}), 400

            cur.execute("INSERT INTO HISTORICO_SENHAS (id_usuario, senha_antiga) VALUES (?, ?)",
                        (id_usuario, senha_hash_atual))

            senha_final = criptografar(senha_nova)

        cur.execute("UPDATE USUARIOS SET nome = ?, email = ?, senha = ? WHERE id_usuario = ?",
                    (nome, email, senha_final, id_usuario))

        if foto:
            # Certifique-size que 'caminho_perfis' está definido globalmente
            foto.save(os.path.join(caminho_perfis, f"perfil_{id_usuario}.jpg"))

        con.commit()
        return jsonify({'mensagem': 'Usuário atualizado com sucesso!'}), 200

    except Exception as e:
        con.rollback()
        print(f"Erro ao editar: {e}")
        return jsonify({'erro': f"Erro interno: {str(e)}"}), 500
    finally:
        cur.close()
        con.close()

@app.route('/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'mensagem': 'Sessão encerrada'}), 200)
    resp.delete_cookie('access_token')
    return resp