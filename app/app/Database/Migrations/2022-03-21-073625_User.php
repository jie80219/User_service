<?php

namespace App\Database\Migrations;

use CodeIgniter\Database\Migration;

class User extends Migration
{
    public function up()
    {
        $this->forge->addField([
            //user table key
            'u_key'           => [
                'type'           => 'INT',
                'constraint'     => 5,
                'unsigned'       => TRUE,
            ],
            'balance'           => [
                'type'           => 'INT',
                'constraint'     => 5,
                'unsigned'       => FALSE
            ],
            "created_at"    => [
                'type'           => 'datetime'
            ],
            "updated_at"    => [
                'type'           => 'datetime'
            ],
            "deleted_at"    => [
                'type'           => 'datetime',
                'null'           => true
            ]
        ]);
        $this->forge->addKey('u_key', TRUE);
        $this->forge->addForeignKey('u_key', 'users', 'id', 'CASCADE', 'CASCADE');
        $this->forge->createTable('wallet');
    }

    public function down()
    {
        //
    }
}
