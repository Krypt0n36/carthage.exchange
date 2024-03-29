const express = require('express');
const jwt = require('jsonwebtoken');
const { pool } = require("./database");
const bodyParser = require('body-parser');
const crypto = require('crypto');
var cors = require('cors');
const { default: axios } = require('axios');
const path = require('path');



let systemFee = 2.5;

const app = express()

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded());
app.use(cors())
app.use(express.static('public'))






function checkExistance(table, { name, value, type = 'string' }, next) {
    if (type == 'string') {
        value = `'${value}'`
    }
    const query = `SELECT id FROM ${table} WHERE ${name}=${value}`;
    pool.query(query)
        .then((result) => {

            next(result.rows.length == 0)

        })
}



function sendNotif(dest_account_id, notif_type, notif_body, notif_link, next = undefined) {
    const ct = new Date().getTime();

    const query = `INSERT INTO notifications (owner_id, type, body, link, creation_time) VALUES (${dest_account_id}, ${notif_type}, '${notif_body}', '${notif_link}', ${ct})`;
    console.log(query)

    pool.query(query)
        .then(() => {
            if (next) {
                next()
            }
        })
        .catch((err) => {
            console.log(err)
        })
}


function deriveOfferOwnerId(offer_id) {
    const query = `SELECT owner_id FROM offers WHERE id=${offer_id}`;
    let owner_id;
    try {
        owner_id = pool.query(query).rows[0].id;
    }
    catch {
        owner_id = undefined;
    }
    return owner_id;
}


app.get('/api/login/check_username_taken', (req, res) => {
    const username = req.query.username;
    if (!username) {
        res.send({ status: 'error' + username })
        return;
    }
    const query = `SELECT id FROM users WHERE username='${username}'`;
    pool.query(query)
        .then(({ rows }) => {
            if (rows.length > 0) {
                // Username is taken
                res.send({ status: 'error', label: 'username_taken' });
            } else {
                res.send({ status: 'ok', label: 'username_available' })
            }
        })
        .catch(err => {
            console.log(err)
        })
})



app.post('/api/verif_token', (req, res) => {
    const token = req.body.token;
    if (!token) {
        res.send({ status: 'error', label: 'Token is not provided' });
        return
    }
    else {
        // verify authentication
        let owner = undefined;
        try {
            owner = jwt.verify(token, process.env.SECRET_KEY);
        } catch {
            res.send({ status: 'auth-error' });
            return;
        }
        if (owner) {
            res.send({ status: 'ok' })
        }
    }
})

app.post('/api/register', (req, res) => {

    const oblig_params = {
        username: req.body.username,
        email: req.body.email,
        password: req.body.password,
        phone_number: req.body.phone_number
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'Cannot be empty!' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return
    }

    const password_hash = crypto.createHash('SHA256').update(oblig_params.password).digest('hex');

    checkExistance('users', { name: 'username', value: oblig_params.username }, (username_unique) => {
        checkExistance('users', { name: 'email', value: oblig_params.email }, (email_unique) => {
            checkExistance('users', { name: 'phone_number', value: oblig_params.phone_number }, (phone_number_unique) => {
                const errors = []
                if (!username_unique) {
                    errors.push({
                        field: 'username',
                        error: 'taken'
                    })
                }
                if (!email_unique) {
                    errors.push({
                        field: 'email',
                        error: 'taken'
                    })
                }
                if (!phone_number_unique) {
                    errors.push({
                        field: 'phone_number',
                        error: 'taken'
                    })
                }
                if (errors.length == 0) {
                    const query = `INSERT INTO users (username, email, phone_number, password_hash) VALUES ('${oblig_params.username}', '${oblig_params.email}', '${oblig_params.phone_number}', '${password_hash}')`
                    pool.query(query)
                        .then((result) => {
                            // Generate token
                            const token = jwt.sign({ username: oblig_params.username }, process.env.SECRET_KEY, { expiresIn: '1h' })
                            res.send({ status: 'ok', token: token })
                        })
                        .catch((err) => {
                            console.log(err)
                            res.send({ status: 'fatal_error', label: 'Database connection error @push_new_user.' })
                        })
                } else {
                    res.send({ status: 'error', fields: errors })
                }
            })
        })
    })



})

app.post('/api/login', (req, res) => {
    fetch('https://ntfy.sh/xcarthage', {
        method: 'POST', // PUT works too
        body: 'Someone logged in'
    })
    const oblig_params = {
        identifier: req.body.identifier,
        password: req.body.password,
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return
    }

    // hash password
    const password_hash = crypto.createHash('SHA256').update(oblig_params.password).digest('hex');

    const query = `SELECT id,username,email FROM users WHERE (username='${oblig_params.identifier}' OR email='${oblig_params.identifier}' OR phone_number='${oblig_params.identifier}') AND password_hash='${password_hash}'`
    pool.query(query)
        .then((result) => {
            if (result.rows.length == 1) {
                const id = result.rows[0].id;
                const username = result.rows[0].username;
                const email = result.rows[0].email;
                const phone_number = result.rows[0].phone_number;

                // authentication sucess
                // create token
                const token = jwt.sign({ username, id }, process.env.SECRET_KEY, { expiresIn: '1h' })
                res.send({ status: 'ok', username, email, phone_number, token })
            } else {
                // auth error
                res.send({ status: 'error', label: 'invalid_credentials' })
            }
        })
        .catch((err) => {
            console.log(err)
            if (err) {
                res.send({ status: 'fatal_error', label: 'Database connection error @auth_user.' })
            }
        })
})



app.post('/api/password_reset/generate_code', (req, res) => {
    const oblig_params = {
        identifier: req.body.identifier,
    }
    
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return
    }
    // check if account exists
    const query = `SELECT id FROM users WHERE email='${oblig_params.identifier}' OR username='${oblig_params.identifier}' OR phone_number='${oblig_params.identifier}'`;
    console.log(query)
    pool.query(query)
        .then(({ rows }) => {
            if (rows.length == 1) {
                // Generate reset code
                const reset_code = crypto.randomInt(0000, 9999).toString().padStart(4, '0');;
                // Send code via email
                console.log('RESET CODE : ' + reset_code);
                // Save code to database
                pool.query(`UPDATE users SET reset_code = '${reset_code}' WHERE id=${rows[0].id} `)
                    .then(() => {
                        // 
                        res.send({ status: 'ok' })
                    })
                    .catch((err) => {
                        console.log(err);
                        res.send({ status: 'fatal_error', label: 'Database connection error @reset_save.' })
                    })
            }else{
                res.send({status:'ok'})
            }
        })
        .catch((err) => {
            res.send({ status: 'fatal_error', label: 'Database connection error @reset_send.' })
        })
})

app.post('/api/password_reset/verif_code', (req, res) => {
    const oblig_params = {
        identifier: req.body.identifier,
        reset_code: req.body.reset_code
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return
    }

    const query = `SELECT id FROM users WHERE (email='${oblig_params.identifier}' OR phone_number='${oblig_params.identifier}' OR username='${oblig_params.identifier}') AND reset_code='${oblig_params.reset_code}'`;
    console.log(query)
    pool.query(query)
        .then(({ rows }) => {
            if (rows.length == 1) {
                // code is correct
                res.send({ status: 'ok', valid: 1 })
            } else {
                res.send({ status: 'ok', valid: 0 })
            }
        })
        .catch((err) => {
            res.send({ status: 'fatal_error', label: 'Database connection error @reset_verif.' })
        })
})


app.post('/api/password_reset/change_password', (req, res) => {
    const oblig_params = {
        identifier: req.body.identifier,
        reset_code: req.body.reset_code,
        new_password: req.body.new_password
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return
    }
    if (oblig_params.reset_code == 'xxxx') {
        res.send({ status: 'error' })
        return;
    }

    const query = `UPDATE users SET password_hash = '${oblig_params.new_password}' WHERE (email='${oblig_params.identifier}' OR phone_number='${oblig_params.identifier}' OR username='${oblig_params.identifier}') AND reset_code='${oblig_params.reset_code}'`;
    pool.query(query)
        .then(() => {
            res.send({ status: 'ok' });
        })
        .catch((err) => {
            console.log(err);
            res.send({ status: 'fatal_error', label: 'Database connection error @reset_change.' })
        })
})

app.post('/api/offers/create', (req, res) => {
    const oblig_params = {
        token: req.body.token,
        crypto_id: req.body.crypto_id,
        min_amount: req.body.min_amount,
        max_amount: req.body.max_amount,
        sell_quote: req.body.sell_quote,
        accept_number: req.body.accept_number,
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return;
    }
    // verify authentication
    let owner = undefined;
    try {
        owner = jwt.verify(oblig_params.token, process.env.SECRET_KEY);
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }

    if (owner) {
        const ct = new Date().getTime()
        const query = `INSERT INTO offers (owner_id, crypto_id, reservoir, min_amount, max_amount, sell_quote, accept_number, creation_time)
        VALUES ('${owner.id}', '${oblig_params.crypto_id}', ${oblig_params.max_amount}, ${oblig_params.min_amount}, ${oblig_params.max_amount}, ${oblig_params.sell_quote}, '${oblig_params.accept_number}', ${ct})`
        pool.query(query)
            .then(() => {
                res.send({ status: 'ok' })
                sendNotif(owner.id, 1, `Your offer of ${oblig_params.crypto_id} at rate ${oblig_params.sell_quote} is now listed, happy selling!`, '');
            })
            .catch((err) => {
                console.log(err);
                res.send({ status: 'fatal_error', label: 'Database connection error @offer_create.' })
            })
    }


})


app.get('/api/widgets', (req, res) => {
    const token = req.query.token;
    // verify authentication
    let owner = undefined;
    try {
        owner = jwt.verify(token, process.env.SECRET_KEY);
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }
    if (!owner) {
        res.send({ status: 'auth-error' });
        return;
    }
    // Count listed offers
    // Calc number views
    // Calc total sold 
    // Get avg resp time
    const query1 = `SELECT COUNT(id) FROM offers WHERE owner_id=${owner.id} AND status='listed'`;
    const query2 = `SELECT SUM(views) FROM offers WHERE owner_id=${owner.id}`;
    const query3 = `SELECT avg_resp_time FROM users WHERE id=${owner.id}`;
    const query4 = `SELECT SUM(offers.amount_sold) FROM offers WHERE owner_id=${owner.id}`;
    pool.query(query1)
        .then((resp1) => {
            const n_listed_offers = resp1.rows[0].count;
            pool.query(query2)
                .then((resp2) => {
                    const total_views = resp2.rows[0].sum;
                    pool.query(query3)
                        .then((resp3) => {
                            const avg_resp_time = resp3.rows[0].avg_resp_time;
                            console.log(query4)
                            pool.query((query4))
                                .then((resp4)=>{
                                    res.send({ status: 'ok', n_listed_offers, total_views, avg_resp_time, total_sold:resp4.rows[0].sum });

                                })

                        })
                        .catch((err) => {
                            console.log(err);
                        })
                })
                .catch((err) => {
                    console.log(err);
                })
        })
        .catch((err) => {
            console.log(err)
        })

})

app.get('/api/offers/offer_details', (req, res) => {
    const offer_id = req.query.offer_id || undefined;

    if (!offer_id) {
        res.send({ status: 'error', label: 'Offer not found.' });
        return
    }

    const query = `SELECT crypto_id, reservoir, min_amount, max_amount, sell_quote FROM offers WHERE id=${offer_id} AND status='listed'`;
    pool.query(query)
        .then((data) => {
            if (data.rows.length == 1) {
                res.send({
                    status: 'ok',
                    crypto_id: data.rows[0]['crypto_id'],
                    reservoir: data.rows[0]['reservoir'],
                    min_amount: data.rows[0]['min_amount'],
                    max_amount: data.rows[0]['max_amount'],
                    sell_quote: data.rows[0]['sell_quote'],
                })

            } else {
                res.send({ status: 'error', label: 'Offer not found.' })
            }
        })
        .catch((err) => {
            console.log(err);
            res.send({ status: 'fatal-error', label: 'Unexpected error @offer_getdetails' })
        })
})

app.get('/api/offers', (req, res) => {
    const filters = {
        crypto_id: req.query.crypto_id,
        max_sell_quote: req.query.max_sell_quote,
        has_amount: req.query.has_amount,
    }
    const sortingField = req.query.sortingField || 'O.creation_time';
    const sortingSense = req.query.sortingSense || 'desc';

    const allowed_sorting_field = ['O.creation_time', 'O.sell_quote', 'U.response_time']
    const allowed_sorting_sense = ['asc', 'desc'];

    if (!(allowed_sorting_field.includes(sortingField) && allowed_sorting_sense.includes(sortingSense))) {
        // invalid sorting field
        res.send({ status: 'error', label: 'invalid sorting.' })
        return
    }

    // Query construction
    let query = `SELECT O.*, U.avg_resp_time, U.username FROM offers O, users U`


    query += ` WHERE O.owner_id=U.id AND O.status='listed' `

    if (filters.crypto_id) {
        query += `AND O.crypto_id='${filters.crypto_id}' `
        if (filters.has_amount || filters.max_sell_quote) {
            query += ' AND '
        }
    }
    if (filters.has_amount) {
        query += ` O.reservoir >= ${filters.has_amount} `
        if (filters.max_sell_quote) {
            query += ' AND '
        }
    }
    if (filters.max_sell_quote) {
        query += ` O.sell_quote <= ${filters.max_sell_quote} `
    }

    query += `ORDER BY ${sortingField} ${sortingSense.toUpperCase()}`

    console.log(query);

    pool.query(query)
        .then(({ rows }) => {
            res.send({ status: 'ok', data: rows })
        })
        .catch((err) => {
            console.log(err);
            res.send({ status: 'fatal_error', label: 'Database connection error @offer_fetch.' })
        })
})

app.get('/api/offers/dashboard_pull', (req, res) => {
    const oblig_params = {
        token: req.query.token,
    }
    if (!oblig_params.token) {
        res.send({ status: 'error', label: 'Token is missing' });
        return;
    }
    // verify authentication
    let owner = { id: undefined, username: undefined };
    try {
        owner = jwt.verify(oblig_params.token, process.env.SECRET_KEY);
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }

    if (!owner.id) {
        res.send({ status: 'auth-error' });
        return;
    }

    const query = `SELECT * FROM offers WHERE owner_id=${owner.id} AND status!='deleted' ORDER BY id DESC`;
    pool.query(query)
        .then(({ rows }) => {
            res.send({ status: 'ok', data: rows })
        })
        .catch((err) => {
            console.log(err);
            res.send({ status: 'fatal_error', label: 'Database connection error @offer_dashfetch.' })
        })


})

app.post('/api/offers/delete', (req, res) => {
    const oblig_params = {
        offer_id: req.body.offer_id,
        token: req.body.token
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return;
    }
    let owner = { id: undefined, username: undefined };
    try {
        owner = jwt.verify(oblig_params.token, process.env.SECRET_KEY);
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }
    if (!owner.id) {
        res.send({ status: 'auth-error' });
        return;
    }
    pool.query(`UPDATE offers SET status='deleted' WHERE id=${oblig_params.offer_id} AND owner_id=${owner.id}`)
        .then(() => {
            res.send({ status: 'ok' })
        })
        .catch((error) => {
            console.log(error)
            res.send({ status: 'error', label: 'Database error @offer_delete.' })

        })

})


app.post('/api/deals/create', (req, res) => {
    const oblig_params = {
        token: req.body.token,
        amount: req.body.amount,
        offer_id: req.body.offer_id,
        wallet_adr: req.body.wallet_adr,
        recv_num: req.body.recv_num,
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return;
    }
    // verify authentication
    let owner = { id: undefined, username: undefined };
    try {
        owner = jwt.verify(oblig_params.token, process.env.SECRET_KEY);
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }

    if (owner.id) {
        const ct = new Date().getTime();
        const query = `INSERT INTO deals (offer_id, owner_id, amount, buyer_d17_number, wallet_adr, creation_time) VALUES (${oblig_params.offer_id}, ${owner.id}, ${oblig_params.amount}, '${oblig_params.recv_num}', '${oblig_params.wallet_adr}', ${ct}) RETURNING id`
        console.log(query)
        pool.query(query)
            .then((out) => {
                // Notify offer owner
                // Pull offer details
                const query = `SELECT * FROM offers WHERE id=${oblig_params.offer_id}`;
                pool.query(query)
                    .then(({ rows }) => {
                        const offer = rows[0];
                        if (!offer) {
                            res.send({ status: 'error', label: 'No such offer #' + oblig_params.offer_id + ' .' })
                            return;
                        }
                        

                       

                        res.send({ status: 'ok', deal_id:out.rows[0].id })
                    })

            })
            .catch((err) => {
                console.log(err);
                res.send({ status: 'fatal_error', label: 'Database connection error @deal_create.' })
            })
    }


})


app.post('/api/deals/set/buyer-placed', (req, res)=>{
    const oblig_params = {
        token: req.body.token,
        deal_id: req.body.deal_id
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return;
    }
    // verify authentication
    let owner_id = undefined;
    try {
        owner_id = jwt.verify(oblig_params.token, process.env.SECRET_KEY).id;
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }
    // verify deal ownership and set status to pending
    const query = `UPDATE deals SET status='buyer-placed' WHERE id=${oblig_params.deal_id} AND owner_id=${owner_id} AND status='created'`
    pool.query(query)
        .then(()=>{
            res.send({status:'ok'})
        })
        .catch((err)=>{
            console.log(err)
            res.send({status:'fatal-error'})
        })
})



app.post('/api/deals/set/seller-placed', (req, res)=>{
    const oblig_params = {
        token: req.query.token,
        deal_id: req.query.deal_id,
        transaction_id: req.query.transaction_id
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return;
    }
    // verify authentication
    let owner_id = undefined;
    try {
        owner_id = jwt.verify(oblig_params.token, process.env.SECRET_KEY).id;
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }

    const query = `UPDATE deals SET status='seller-placed', transaction_id='${oblig_params.transaction_id}' FROM offers WHERE deals.id=${oblig_params.deal_id} AND offer_id=offers.id AND offers.owner_id=${owner_id} AND deals.status='buyer-paid'`
    console.log(query)
    pool.query(query)
        .then(()=>{
            res.send({status:'ok'})
        })
        .catch((err)=>{
            console.log(err)
            res.send({status:'fatal-error'})
        })
})

app.get('/api/deals/status', (req, res)=>{
    const oblig_params = {
        token: req.query.token,
        deal_id: req.query.deal_id,
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return;
    }
    // verify authentication
    let owner_id = undefined;
    try {
        owner_id = jwt.verify(oblig_params.token, process.env.SECRET_KEY).id;
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }

    const query = `SELECT deals.status FROM deals, offers WHERE deals.offer_id=offers.id AND deals.id=${oblig_params.deal_id} AND (deals.owner_id=${owner_id} OR offers.owner_id=${owner_id})`
    pool.query(query)
        .then(({rows})=>{
            if(rows.length>0){
                res.send({status:'ok',deal_status:rows[0].status})
            }else{
                res.send({status:'error', label:'Deal does not exist or false ownership.'})
            }
        })
        .catch(err=>{
            console.log(err)
            res.send({status:'fatal-error'})
        })

})

app.get('/api/deals/info', (req, res)=>{
    const oblig_params = {
        token: req.query.token,
        deal_id: req.query.deal_id
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return;
    }
    // verify authentication
    let owner_id = undefined;
    try {
        owner_id = jwt.verify(oblig_params.token, process.env.SECRET_KEY).id;
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }
    const query = `SELECT D.amount, O.sell_quote, D.status FROM deals D, offers O WHERE D.owner_id = ${owner_id} AND D.offer_id = O.id AND D.id=${oblig_params.deal_id}`;
    pool.query(query)
        .then(resp=>{
            if(resp.rows[0].amount){
                console.log('=========')
                console.log(resp.rows[0].amount)
                console.log(resp.rows[0].sell_quote)
                console.log(resp.rows[0].amount * parseFloat(resp.rows[0].sell_quote) )
                console.log('=========')

                res.send({status:'ok', dealStatus:resp.rows[0].status, total: parseFloat(resp.rows[0].amount) * parseFloat(resp.rows[0].sell_quote) * (1+systemFee/100)})
            }else{
                res.send({status:'error'})
            }
        })
        .catch(err=>{
            console.log(err)
            res.send({status:'fatal-error'})
        })

})

app.get('/api/deals', (req, res) => {
    const oblig_params = {
        token: req.query.token
    }
    let errors = [];
    for (const key in oblig_params) {
        if (!oblig_params[key] || oblig_params[key].length == 0) {
            errors.push({ name: key, label: 'missing' })
        }
    }
    if (errors.length > 0) {
        res.send({ status: 'error', fields: errors })
        return;
    }
    // verify authentication
    let owner_id = undefined;
    try {
        owner_id = jwt.verify(oblig_params.token, process.env.SECRET_KEY).id;
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }
    // fetch deals associated with owner_id
    const query = `SELECT D.id, D.amount, D.creation_time, F.crypto_id, F.sell_quote FROM deals D, offers F WHERE D.offer_id = F.id AND F.owner_id = ${owner_id} AND D.creation_time + 3600000 >= ${new Date().getTime()} AND D.status='buyer-placed-confirmed' ORDER BY D.id DESC`;
    console.log(query)
    pool.query(query)
        .then(({ rows }) => {
            res.send({ status: 'ok', data: rows })
        })
        .catch((err) => {
            console.log(err);
            res.send({ status: 'fatal_error', label: 'Database connection error @deals_fetch.' })
        })
})

app.post('/api/deals/accept', (req, res)=>{
    const token = req.body.token;
    const deal_id = req.body.deal_id;
    const transaction_id = req.body.transaction_id;

    let owner_id = undefined;
    try {
        owner_id = jwt.verify(token, process.env.SECRET_KEY).id;
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }

    const query = `UPDATE deals SET status='seller-placed', transaction_id='${transaction_id}' FROM offers WHERE deals.id=${deal_id} AND deals.offer_id=offers.id AND offers.owner_id = ${owner_id}`


    pool.query(query)
        .then((r)=>{
            if(r.rowCount>0){
                res.send({status:'ok'})
            }
            else{
                res.send({status:'ownership-error'})
            }
        })
        .catch(err=>{
            console.log(err)
            res.send({status:'error'})
        })
})

app.post('/api/deals/reject', (req, res) => {
    const token = req.body.token;
    const deal_id = req.body.deal_id;

    let owner_id = undefined;
    try {
        owner_id = jwt.verify(token, process.env.SECRET_KEY).id;
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }

    const query = `UPDATE deals SET status='rejected' FROM offers WHERE deals.id=${deal_id} AND deals.offer_id=offers.id AND offers.owner_id = ${owner_id}`
    console.log(query)
    pool.query(query)
        .then(() => {
            res.send({ status: 'ok' })
        })
        .catch((err) => {
            console.log(err)
            res.send({ status: 'fatal-error' })
        })
})




app.get('/api/notifications', (req, res) => {
    const oblig_params = {
        token: req.query.token
    }
    const lastSyncTime = req.query.lastSyncTime || 0;

    // verify authentication
    let owner_id = undefined;
    try {
        owner_id = jwt.verify(oblig_params.token, process.env.SECRET_KEY).id;
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }

    const query = `SELECT * FROM notifications WHERE owner_id=${owner_id} AND creation_time>=${lastSyncTime} ORDER BY id DESC`;
    pool.query(query)
        .then(({ rows }) => {
            res.send({ status: 'ok', data: rows })
            return;
        })
        .catch((err) => {
            console.log(err);
            res.send({ status: 'fatal_error', label: 'Database connection error @notifications_fetch.' })
        })
})



app.get('/api/admin/pull', (req, res)=>{
    const passphrase = req.query.passphrase; 
    console.log(passphrase)
    

    if(passphrase && passphrase=='abc123'){
    }else{
        res.send({status:'auth-error'})
        return;
    }

    const query1 = `SELECT deals.id, deals.buyer_d17_number, deals.amount, offers.sell_quote FROM deals, offers WHERE offers.id=deals.offer_id AND deals.status='buyer-placed'`
    pool.query(query1)
        .then((data1)=>{
            const query2 = `SELECT deals.id, deals.transaction_id, deals.amount, offers.crypto_id, offers.sell_quote FROM deals, offers WHERE offers.id=deals.offer_id AND deals.status='seller-placed'`
            pool.query(query2)
                .then((data2)=>{
                    const query3 = `SELECT deals.id, deals.amount, deals.wallet_adr, offers.sell_quote, offers.crypto_id FROM deals, offers WHERE offers.id=deals.offer_id AND deals.status='seller-placed-confirmed'`
                    pool.query(query3)
                        .then((data3)=>{
                            const query4 = `SELECT deals.id, deals.amount, offers.sell_quote, offers.accept_number FROM deals, offers WHERE offers.id=deals.offer_id AND deals.status='crypto-forwarded'`
                            pool.query(query4)
                                .then((data4)=>{
                                    
                                    res.send({
                                        status:'ok',
                                        d17_pending:data1.rows,
                                        crypto_pending:data2.rows,
                                        d17_req:data4.rows,
                                        crypto_req:data3.rows
                                    })

                                })
                                .catch((err)=>{
                                    console.log(err)
                                    res.send({status:'fatal-error'})
                                })
                        })
                        .catch((err)=>{
                            console.log(err)
                            res.send({status:'fatal-error'})
                        })
                })
                .catch((err)=>{
                    console.log(err)
                    res.send({status:'fatal-error'})
                })
            
        })
        .catch((err)=>{
            console.log(err)
            res.send({status:'fatal-error'})
        })
})


app.post('/api/admin/make_d17_confirmation', (req, res)=>{
    const sender = req.body.sender;
    const recv_sum = req.body.recv_sum;

    const query = `UPDATE deals SET status='buyer-placed-confirmed' FROM offers WHERE deals.offer_id=offers.id AND deals.buyer_d17_number='${sender}' AND (deals.amount*offers.sell_quote)*(1+0.025)<=${recv_sum} AND deals.status='buyer-placed' RETURNING deals.id`
    console.log(query)
    pool.query(query)
        .then(r=>{

            const deal_id = r.rows[0].id;

            const query2 = `SELECT O.owner_id AS offer_owner_id, D.owner_id AS deal_owner_id, D.amount, O.crypto_id, O.sell_quote FROM deals D, offers O WHERE D.offer_id=O.id AND D.id=${deal_id}`

            pool.query(query2)
                .then(r2=>{
                    const notif_body = `New buyer has opened a deal of ${r2.rows[0].amount} USD worth of ${r2.rows[0].crypto_id} (Sell quote ${r2.rows[0].sell_quote}), money is on the table. Click to view deal info. Hurry before the offer expires.`
                    sendNotif(r2.rows[0].offer_owner_id, 0, notif_body, '');
                })

           

            res.send({status:'ok', c:r.rowCount})
        })
        .catch(err=>{
            console.log(err)
            res.send({status:'fatal-error'})
        })
})  

app.post('/api/admin/make_crypto_confirmation', (req, res)=>{
    const transaction_id = req.body.transaction_id;
    const recv_sum = req.body.recv_sum;
    const crypto_id = req.body.crypto_id;

    const query = `UPDATE deals SET status='seller-placed-confirmed' FROM offers WHERE deals.offer_id=offers.id AND deals.transaction_id='${transaction_id}' AND offers.crypto_id='${crypto_id.toUpperCase()}' AND deals.amount<=${recv_sum} AND deals.status='seller-placed'`
    
    console.log(query)
    pool.query(query)
        .then(r=>{

            // update offer reservoir
            const query2 = `UPDATE offers SET offers.amount_sold=offers.amount_sold+${recv_sum} FROM deals WHERE deals.offer_id=offers.id AND deals.transaction_id=${transaction_id} AND offers.crypto_id='${crypto_id.toUpperCase()}' `
            console.log(query2)
            pool.query(query)
            res.send({status:'ok', c:r.rowCount})
        })
        .catch(err=>{
            console.log(err)
            res.send({status:'fatal-error'})
        })
})  

app.post('/api/admin/record_crypto_payment', (req, res)=>{
    const wallet_adr = req.body.wallet_adr;
    const sent_sum = req.body.sent_sum;
    const crypto_id = req.body.crypto_id;
    const query = `UPDATE deals SET status='crypto-forwarded' FROM offers WHERE deals.offer_id=offers.id AND deals.wallet_adr='${wallet_adr}' AND offers.crypto_id='${crypto_id.toUpperCase()}' AND deals.amount<=${sent_sum} AND deals.status='seller-placed-confirmed'`
    console.log(query)
    pool.query(query)
        .then(r=>{
            res.send({status:'ok', c:r.rowCount})
        })
        .catch(err=>{
            console.log(err)
            res.send({status:'fatal-error'})
        })
})  


app.post('/api/admin/record_d17_payment', (req, res)=>{
    const d17_num = req.body.d17_num;
    const sent_sum = req.body.sent_sum;

    const query = `UPDATE deals SET status='deal-closed' FROM offers WHERE deals.offer_id=offers.id AND offers.accept_number='${d17_num}' AND deals.amount*offers.sell_quote<=${sent_sum} AND deals.status='crypto-forwarded'`
    console.log(query)
    pool.query(query)
        .then(r=>{
            res.send({status:'ok', c:r.rowCount})
        })
        .catch(err=>{
            console.log(err)
            res.send({status:'fatal-error'})
        })
})  

app.post('/api/notifications/mark_seen', (req, res) => {
    const oblig_params = {
        token: req.body.token,
        lastSeenId: req.body.lastSeenId,
    }
    // verify authentication
    let owner_id = undefined;
    try {
        owner_id = jwt.verify(oblig_params.token, process.env.SECRET_KEY).id;
    } catch {
        res.send({ status: 'auth-error' });
        return;
    }

    const query = `UPDATE notifications SET seen=1 WHERE owner_id=${owner_id} AND id<=${oblig_params.lastSeenId}`;
    pool.query(query)
        .then(() => {
            res.send({ status: 'ok' })
        })
        .catch((err) => {
            console.log(err)
            res.send({ status: 'fatal-error', label: 'Error @notifications_mark_seen' });
        })
})



app.get('/api/params/system-fee', (req, res )=>{
    res.send(systemFee.toString())
})

app.get('/api/params/recv_number', (req, res)=>{
    res.send('28077652')
})

app.get('/api/params/wallet_addr/bitcoin', (req, res)=>{
    res.send('bc1qw04c0pgh6a8nqj3cs89ac2u2a3yt9fhkvn6pl6')
})
app.get('/api/params/wallet_addr/tether', (req, res)=>{
    res.send('0x55C1D6d1524cBeD2C8217EE23Ac11C63F38F2156')
})
app.get('/api/params/wallet_addr/ethereum', (req, res)=>{
    res.send('0x55C1D6d1524cBeD2C8217EE23Ac11C63F38F2156')
})

app.get('*', (req,res) =>{
    res.sendFile(path.join(__dirname+'/public/index.html'));
});

app.listen(process.env.PORT || 8080, () => {
    console.log('[+] Server Started.')
})
