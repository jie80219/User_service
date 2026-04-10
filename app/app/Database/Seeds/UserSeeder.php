<?php

namespace App\Database\Seeds;

use CodeIgniter\Database\Seeder;

class UserSeeder extends Seeder
{
    public function run()
    {
        for ($i = 0; $i < 5; $i++) {
            $this->db->transStart();

            if ($i == 0) {
                $balance = 900000000;
            } else if ($i == 1) {
                $balance = 0;
            } else {
                $balance = random_int(0, 100000);
            }

            $this->db->table("users")
                ->insert([
                    "email" => "user" . ($i + 1) . "@anser.io",
                    "password" => password_hash("password", PASSWORD_DEFAULT),
                    "created_at" => date("Y-m-d H:i:s"),
                    "updated_at" => date("Y-m-d H:i:s")
                ]);

            $this->db->table("wallet")
                ->insert([
                    "u_key" => $i + 1,
                    "balance" => $balance,
                    "created_at" => date("Y-m-d H:i:s"),
                    "updated_at" => date("Y-m-d H:i:s")
                ]);

            $this->db->table("history")
                ->insert([
                    "u_key" => $i + 1,
                    "type" => "stored",
                    "amount" => $balance,
                    "created_at" => date("Y-m-d H:i:s"),
                    "updated_at" => date("Y-m-d H:i:s")
                ]);
            $this->db->transComplete();
        }
    }
}