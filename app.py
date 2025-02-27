from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import check_password_hash, generate_password_hash
import logging
import MySQLdb.cursors

# Configuración de la aplicación
app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'hospital'
app.secret_key = 'mysecretkey'

# Inicialización de la base de datos
mysql = MySQL(app)

logging.basicConfig(level=logging.DEBUG)

@app.route('/hash_passwords')
def hash_passwords():
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT rfc, password FROM medico")
        medicos = cursor.fetchall()

        for medico in medicos:
            rfc = medico[0]
            password = medico[1]
            if not password.startswith('pbkdf2:sha256'):
                hashed_password = generate_password_hash(password)
                cursor.execute("UPDATE medico SET password = %s WHERE rfc = %s", (hashed_password, rfc))
                logging.debug(f"Password for {rfc} hashed as {hashed_password}")

        mysql.connection.commit()
        return "Contraseñas hasheadas y actualizadas exitosamente."
    except Exception as e:
        logging.error(f"Error al hashear las contraseñas: {e}")
        return "Ocurrió un error al actualizar las contraseñas."
    finally:
        cursor.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        rfc = request.form['rfc']
        password = request.form['password']
        logging.debug(f"Intento de inicio de sesión con RFC: {rfc}")

        cursor = mysql.connection.cursor()
        try:
            cursor.execute('SELECT password, rol FROM medico WHERE rfc = %s', (rfc,))
            medico = cursor.fetchone()

            if medico:
                stored_password_hash = medico[0]
                rol = medico[1]
                logging.debug(f"Usuario encontrado: {rfc}, Rol: {rol}")
                logging.debug(f"Stored hash: {stored_password_hash}")
                logging.debug(f"Input password: {password}")

                # Verificación manual del hash
                hash_check = check_password_hash(stored_password_hash, password)
                logging.debug(f"Hash check result: {hash_check}")

                if hash_check:
                    session['rfc'] = rfc
                    session['rol'] = rol
                    logging.debug(f"Usuario autenticado: {rfc} con rol: {rol}")
                    if rol == 'Medico Admin':
                        logging.debug("Redirigiendo al dashboard de administrador")
                        return redirect(url_for('dashboard_admin'))
                    elif rol == 'Médico':
                        logging.debug("Redirigiendo al dashboard de médico")
                        return redirect(url_for('dashboard_medico'))
                    else:
                        logging.debug(f"Rol desconocido para el RFC: {rfc}")
                        flash('Rol desconocido', 'danger')
                else:
                    logging.debug(f"Contraseña incorrecta para el RFC: {rfc}")
                    flash('RFC o contraseña incorrectos', 'danger')
            else:
                logging.debug(f"Usuario no encontrado para el RFC: {rfc}")
                flash('RFC o contraseña incorrectos', 'danger')
        except Exception as e:
            logging.error(f"Error durante el inicio de sesión: {e}")
            flash('Ocurrió un error durante el inicio de sesión', 'danger')
        finally:
            cursor.close()
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('rfc', None)
    session.pop('rol', None)
    return redirect(url_for('index'))

@app.route('/dashboard_admin')
def dashboard_admin():
    if 'rfc' in session and session['rol'] == 'Medico Admin':
        logging.debug(f"Accediendo al dashboard de administrador con RFC: {session['rfc']}")
        return render_template('dashboard_admin.html')
    else:
        logging.debug(f"Intento de acceso no autorizado al dashboard de administrador. Sesión: {session}")
        return redirect(url_for('login'))

@app.route('/dashboard_medico')
def dashboard_medico():
    if 'rfc' in session and session['rol'] == 'Médico':
        logging.debug(f"Accediendo al dashboard de médico con RFC: {session['rfc']}")
        return render_template('dashboard_medico.html')
    else:
        logging.debug(f"Intento de acceso no autorizado al dashboard de médico. Sesión: {session}")
        return redirect(url_for('dashboard_admin') if session.get('rol') == 'Medico Admin' else 'login')


@app.route('/consultas/<int:id_paciente>')
def consultas(id_paciente):
    if 'rfc' not in session:
        return redirect(url_for('login'))

    rfc_medico = session['rfc']
    try:
        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM paciente WHERE id = %s AND rfc_medico = %s', (id_paciente, rfc_medico))
        paciente = cur.fetchone()
        cur.close()

        if paciente:
            paciente_data = {
                'id': paciente[0],
                'nombre_completo': paciente[1],
                'fecha_nacimiento': paciente[2],
                'enfermedades_cronicas': paciente[3],
                'alergias': paciente[4],
                'antecedentes_familiares': paciente[5]
            }
            logging.debug(f"Paciente encontrado: {paciente_data}")
            return render_template('consultas.html', paciente=paciente_data)
        else:
            logging.debug(f"Paciente con id {id_paciente} no encontrado o no pertenece al médico {rfc_medico}")
            return redirect(url_for('dashboard_medico' if session['rol'] == 'Médico' else 'dashboard_admin'))
    except Exception as e:
        logging.error(f"Error al realizar la consulta: {str(e)}")
        flash(f'Ocurrió un error: {str(e)}', 'danger')
        return redirect(url_for('dashboard_medico' if session['rol'] == 'Médico' else 'dashboard_admin'))



@app.route('/buscar_pacientes', methods=['POST'])
def buscar_pacientes():
    if 'rfc' not in session:
        return redirect(url_for('login'))

    nombre_paciente = request.form['nombre_paciente']
    rfc_medico = session['rfc']

    logging.debug(f"Buscando pacientes con nombre parecido a: {nombre_paciente} y rfc_medico: {rfc_medico}")

    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT p.id, p.nombre_completo 
        FROM paciente p
        JOIN medico_paciente mp ON p.id = mp.id_paciente
        WHERE p.nombre_completo LIKE %s AND mp.rfc_medico = %s
    """, ("%" + nombre_paciente + "%", rfc_medico))

    resultados = cursor.fetchall()
    cursor.close()

    logging.debug(f"Resultados encontrados: {resultados}")

    return render_template('resultados_busqueda.html', resultados=resultados)

@app.route('/consultar_paciente/<int:id>')
def consultar_paciente(id):
    if 'rfc' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM paciente WHERE id = %s", (id,))
    paciente = cursor.fetchone()
    cursor.close()

    if paciente:
        return render_template('consultar_paciente.html', paciente=paciente)
    else:
        return redirect(url_for('buscar_pacientes'))

@app.route('/seleccionar_paciente', methods=['POST'])
def seleccionar_paciente():
    id_paciente = request.form.get('selected_patient')
    if id_paciente:
        return redirect(url_for('consultar_paciente', id=id_paciente))
    else:
        return redirect(url_for('buscar_pacientes'))


@app.route('/guardar_paciente/<int:id>', methods=['POST'])
def guardar_paciente(id):
    if 'rfc' not in session:
        return jsonify(success=False, message='Debe iniciar sesión primero')
    
    nombre_completo = request.form.get('nombre_completo')
    fecha_nacimiento = request.form.get('fecha_nacimiento')
    enfermedades_cronicas = request.form.get('enfermedades_cronicas')
    alergias = request.form.get('alergias')
    antecedentes_familiares = request.form.get('antecedentes_familiares')
    rfc_medico = session.get('rfc')
    
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("""
            UPDATE paciente 
            SET nombre_completo=%s, fecha_nacimiento=%s, enfermedades_cronicas=%s, alergias=%s, antecedentes_familiares=%s
            WHERE id=%s AND EXISTS (
                SELECT 1 FROM medico_paciente 
                WHERE medico_paciente.id_paciente = paciente.id 
                AND medico_paciente.rfc_medico = %s
            )
        """, (nombre_completo, fecha_nacimiento, enfermedades_cronicas, alergias, antecedentes_familiares, id, rfc_medico))
        mysql.connection.commit()
        return jsonify(success=True, message='Información del paciente actualizada correctamente')
    except Exception as e:
        mysql.connection.rollback()
        return jsonify(success=False, message=str(e))
    finally:
        cursor.close()


@app.route('/exploracion_diagnostico/<int:id>')
def exploracion_diagnostico(id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM paciente WHERE id = %s", (id,))
    paciente = cursor.fetchone()
    cursor.close()
    return render_template('exploracion_diagnostico.html', paciente=paciente)

@app.route('/guardar_consulta/<int:id>', methods=['POST'])
def guardar_consulta(id):
    if 'rfc' not in session:
        logging.debug("Sesión no encontrada. Redirigiendo a login.")
        return redirect(url_for('login'))

    fecha = request.form['fecha']
    peso = request.form['peso']
    altura = request.form['altura']
    temperatura = request.form['temperatura']
    latidosxmin = request.form ['latidosxmin']
    oxigenacion = request.form['oxigenacion']
    glucosa = request.form['glucosa']
    edad = request.form['edad']
    sintomas = request.form['sintomas']
    diagnostico = request.form['diagnostico']
    tratamiento = request.form['tratamiento']
    estudios = request.form['estudios']
    
   
    if not all([fecha, peso, altura, temperatura, latidosxmin, oxigenacion, glucosa, edad, sintomas, diagnostico, tratamiento, estudios]):
        return redirect(url_for('exploracion_diagnostico', id=id))
    
    rfc_medico = session['rfc']  
    
    cursor = mysql.connection.cursor()
    cursor.execute("""
        INSERT INTO consultas (id_paciente, rfc_medico, fecha, peso, altura, temperatura, latidosxmin, oxigenacion, glucosa, edad, sintomas, diagnostico, tratamiento, estudios)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (id, rfc_medico, fecha, peso, altura, temperatura, latidosxmin, oxigenacion,  glucosa, edad, sintomas, diagnostico, tratamiento, estudios))
    mysql.connection.commit()
    consulta_id = cursor.lastrowid
    cursor.close()
    return redirect(url_for('ver_receta', consulta_id=consulta_id))

@app.route('/ver_receta/<int:consulta_id>')
def ver_receta(consulta_id):
    if 'rfc' not in session:
        logging.debug("Sesión no encontrada. Redirigiendo a login.")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT consultas.*, paciente.nombre_completo AS nombre_paciente, medico.nombre_completo AS nombre_medico, medico.cedula_profesional
        FROM consultas
        JOIN paciente ON consultas.id_paciente = paciente.id
        JOIN medico ON consultas.rfc_medico = medico.rfc
        WHERE consultas.id = %s
    """, (consulta_id,))
    consulta = cursor.fetchone()
    cursor.close()
    
    return render_template('receta.html', consulta=consulta)
###
@app.route('/ver_receta2/<int:consulta_id>')
def ver_receta2(consulta_id):
    if 'rfc' not in session:
        logging.debug("Sesión no encontrada. Redirigiendo a login.")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT consultas.*, paciente.nombre_completo AS nombre_paciente, medico.nombre_completo AS nombre_medico, medico.cedula_profesional, paciente.id AS id_paciente
        FROM consultas
        JOIN paciente ON consultas.id_paciente = paciente.id
        JOIN medico ON consultas.rfc_medico = medico.rfc
        WHERE consultas.id = %s
    """, (consulta_id,))
    consulta = cursor.fetchone()
    cursor.close()
    
    return render_template('receta2.html', consulta=consulta)


####
@app.route('/ver_receta3/<int:consulta_id>')
def ver_receta3(consulta_id):
    if 'rfc' not in session:
        logging.debug("Sesión no encontrada. Redirigiendo a login.")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT consultas.*, paciente.nombre_completo AS nombre_paciente, medico.nombre_completo AS nombre_medico, medico.cedula_profesional, paciente.id AS id_paciente
        FROM consultas
        JOIN paciente ON consultas.id_paciente = paciente.id
        JOIN medico ON consultas.rfc_medico = medico.rfc
        WHERE consultas.id = %s
    """, (consulta_id,))
    consulta = cursor.fetchone()
    cursor.close()
    
    return render_template('receta3.html', consulta=consulta)



####
@app.route('/citas_paciente/<int:id_paciente>')
def citas_paciente(id_paciente):
    if 'rfc' not in session:
        logging.debug("Sesión no encontrada. Redirigiendo a login.")
        return redirect(url_for('login'))

    rfc_medico = session['rfc']

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT * FROM consultas
        WHERE id_paciente = %s AND rfc_medico = %s
    """, (id_paciente, rfc_medico))
    citas = cursor.fetchall()
    
    cursor.execute("SELECT nombre_completo FROM paciente WHERE id = %s", (id_paciente,))
    paciente = cursor.fetchone()
    cursor.close()
    if not citas:
        flash('')
    return render_template('citas_paciente.html', citas=citas, id_paciente=id_paciente, paciente_nombre=paciente['nombre_completo'])

@app.route('/registro_paciente', methods=['GET', 'POST'])
def registro_paciente():
    if request.method == 'POST':
        nombre_completo = request.form['nombre_completo']
        fecha_nacimiento = request.form['fecha_nacimiento']
        enfermedades_cronicas = request.form['enfermedades_cronicas']
        alergias = request.form['alergias']
        antecedentes_familiares = request.form['antecedentes_familiares']
        rfc_medico = session['rfc']  

        cursor = mysql.connection.cursor()
        cursor.execute("""
            SELECT p.id 
            FROM paciente p
            JOIN medico_paciente mp ON p.id = mp.id_paciente
            WHERE p.nombre_completo = %s AND mp.rfc_medico = %s
        """, (nombre_completo, rfc_medico))
        paciente_existente = cursor.fetchone()

        if paciente_existente:
            flash('El paciente ya está registrado con este médico.', 'warning')
            return redirect(url_for('registro_paciente'))

        cursor.execute("""
            INSERT INTO paciente (nombre_completo, fecha_nacimiento, enfermedades_cronicas, alergias, antecedentes_familiares)
            VALUES (%s, %s, %s, %s, %s)
        """, (nombre_completo, fecha_nacimiento, enfermedades_cronicas, alergias, antecedentes_familiares))
        paciente_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO medico_paciente (rfc_medico, id_paciente)
            VALUES (%s, %s)
        """, (rfc_medico, paciente_id))
        
        mysql.connection.commit()
        cursor.close()
        flash('Paciente registrado correctamente.', 'success')
        return redirect(url_for('registro_paciente'))
    return render_template('registro_paciente.html')

@app.route('/ver_pacientes')
def ver_pacientes():
    if 'rfc' not in session:
        return redirect(url_for('login'))

    rfc_medico = session['rfc']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT p.id, p.nombre_completo 
        FROM paciente p
        JOIN medico_paciente mp ON p.id = mp.id_paciente
        WHERE mp.rfc_medico = %s AND p.oculto = 0
    """, [rfc_medico])
    pacientes = cursor.fetchall()
    cursor.close()

    return render_template('ver_pacientes.html', pacientes=pacientes)


@app.route('/ocultar_paciente/<int:id>', methods=['POST'])
def ocultar_paciente(id):
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("UPDATE paciente SET oculto = 1 WHERE id = %s", (id,))
        mysql.connection.commit()
        cursor.close()
        return jsonify(success=True, message="El paciente ha sido ocultado correctamente.")
    except Exception as e:
        mysql.connection.rollback()
        cursor.close()
        return jsonify(success=False, message=str(e))

@app.route('/consultas_paciente/<int:id>')
def consultas_paciente(id):
    if 'rfc' not in session:
        logging.debug("Sesión no encontrada. Redirigiendo a login.")
        return redirect(url_for('login'))

    rfc_medico = session['rfc']
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT * FROM consultas
            WHERE id_paciente = %s AND rfc_medico = %s
        """, (id, rfc_medico))
        consultas = cursor.fetchall()
        
        cursor.execute("SELECT nombre_completo FROM paciente WHERE id = %s", (id,))
        paciente = cursor.fetchone()
        cursor.close()
        
        return render_template('consultas_paciente.html', consultas=consultas, id_paciente=id, paciente_nombre=paciente['nombre_completo'])
    except Exception as e:
        logging.error(f"Error al obtener las consultas del paciente: {str(e)}")
        flash(f'Ocurrió un error: {str(e)}', 'danger')
        return redirect(url_for('dashboard_medico' if session['rol'] == 'Médico' else 'dashboard_admin'))

@app.route('/ver_consulta/<int:id>')
def ver_consulta(id):
    if 'rfc' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT c.*, p.nombre_completo
        FROM consultas c
        JOIN paciente p ON c.id_paciente = p.id
        WHERE c.id = %s
    """, (id,))
    consulta = cursor.fetchone()
    cursor.close()

    return render_template('ver_consulta.html', consulta=consulta)

@app.route('/agenda')
def agenda():
    if 'rfc' not in session:
        flash('Debe iniciar sesión primero', 'danger')
        return redirect(url_for('login'))
    return render_template('agenda.html')

@app.route('/citas_del_dia', methods=['GET'])
def citas_del_dia():
    if 'rfc' not in session:
        logging.debug("Sesión no encontrada. Redirigiendo a login.")
        return redirect(url_for('login'))

    fecha = request.args.get('fecha')
    rfc_medico = session['rfc']

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT consultas.*, paciente.nombre_completo AS nombre_paciente
        FROM consultas
        JOIN paciente ON consultas.id_paciente = paciente.id
        WHERE consultas.rfc_medico = %s AND consultas.fecha = %s
    """, (rfc_medico, fecha))
    consultas = cursor.fetchall()
    cursor.close()
    
    return render_template('citas_del_dia.html', consultas=consultas, fecha=fecha)


@app.route('/ver_receta4/<int:consulta_id>')
def ver_receta4(consulta_id):
    if 'rfc' not in session:
        logging.debug("Sesión no encontrada. Redirigiendo a login.")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT consultas.*, paciente.nombre_completo AS nombre_paciente, medico.nombre_completo AS nombre_medico, medico.cedula_profesional, paciente.id AS id_paciente
        FROM consultas
        JOIN paciente ON consultas.id_paciente = paciente.id
        JOIN medico ON consultas.rfc_medico = medico.rfc
        WHERE consultas.id = %s
    """, (consulta_id,))
    consulta = cursor.fetchone()
    cursor.close()
    
    return render_template('receta4.html', consulta=consulta)



############################################################################################################
@app.route('/buscar_medico', methods=['GET', 'POST'])
def buscar_medico():
    if request.method == 'POST':
        rfc = request.form.get('rfc')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM medico WHERE rfc = %s", [rfc])
        medico = cursor.fetchone()
        cursor.close()
        if medico:
            return render_template('buscar_medico.html', medico=medico)
        else:
            return render_template('buscar_medico.html')
    return render_template('buscar_medico.html')

@app.route('/guardar_medico/<string:rfc>', methods=['POST'])
def guardar_medico(rfc):
    if 'rfc' not in session:
        return jsonify(success=False, message='Debe iniciar sesión primero')

    try:
        nombre_completo = request.form['nombre_completo']
        cedula_profesional = request.form['cedula_profesional']
        correo = request.form['correo']
        password = request.form['password']
        rol = request.form['rol']

        if rol not in ['Médico', 'Medico Admin']:
            return jsonify(success=False, message='Rol inválido')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT password FROM medico WHERE rfc = %s", [rfc])
        stored_password = cursor.fetchone()['password']

        if password != stored_password:
            hashed_password = generate_password_hash(password)
        else:
            hashed_password = password

        cursor.execute("""
            UPDATE medico 
            SET nombre_completo=%s, cedula_profesional=%s, correo=%s, password=%s, rol=%s 
            WHERE rfc=%s
        """, (nombre_completo, cedula_profesional, correo, hashed_password, rol, rfc))
        mysql.connection.commit()
        cursor.close()
        
        return jsonify(success=True, message='Información del médico actualizada correctamente')
    
    except Exception as e:
        return jsonify(success=False, message=f'Ocurrió un error: {str(e)}')

@app.route('/ver_medicos')
def ver_medicos():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM medico WHERE oculto = FALSE")
    medicos = cursor.fetchall()
    cursor.close()
    return render_template('ver_medicos.html', medicos=medicos)

@app.route('/ocultar_medico/<rfc>', methods=['POST'])
def ocultar_medico(rfc):
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("UPDATE medico SET oculto = 1 WHERE rfc = %s", (rfc,))
        mysql.connection.commit()
        cursor.close()
        return jsonify(success=True, message="El médico ha sido ocultado correctamente.")
    except Exception as e:
        mysql.connection.rollback()
        cursor.close()
        return jsonify(success=False, message=str(e))

@app.route('/registrar_medico', methods=['GET', 'POST'])
def registrar_medico():
    if request.method == 'POST':
        rfc = request.form['rfc']
        nombre_completo = request.form['nombre_completo']
        cedula_profesional = request.form['cedula_profesional']
        correo = request.form['correo']
        password = request.form['password']
        rol = request.form['rol']
        
        
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM medico WHERE rfc = %s', (rfc,))
        medico_existente = cursor.fetchone()
        if medico_existente:
            return jsonify(success=False, message='El médico ya está registrado')
        
        hashed_password = generate_password_hash(password)

        cursor.execute('INSERT INTO medico (rfc, nombre_completo, cedula_profesional, correo, password, rol) VALUES (%s, %s, %s, %s, %s, %s)', (rfc, nombre_completo, cedula_profesional, correo, hashed_password, rol))
        mysql.connection.commit()
        cursor.close()

        return jsonify(success=True, message='Médico registrado correctamente')
    return render_template('registrar_medico.html')

@app.errorhandler(404)
def paginano(e):
    return 'Revisa tu sintaxis: No encontré nada', 404

if __name__ == '__main__':
    app.run(port=5000, debug=True)

