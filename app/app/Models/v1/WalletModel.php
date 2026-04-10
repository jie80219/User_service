<?php

namespace App\Models\v1;

use CodeIgniter\Model;
use App\Entities\v1\WalletEntity;

class WalletModel extends Model
{
    protected $DBGroup          = USE_DB_GROUP;
    protected $table            = 'wallet';
    protected $primaryKey       = 'u_key';
    protected $useAutoIncrement = true;
    protected $insertID         = 0;
    protected $returnType       = WalletEntity::class;
    protected $useSoftDeletes   = true;
    protected $protectFields    = true;
    protected $allowedFields    = ['u_key', 'balance'];

    // Dates
    protected $useTimestamps = true;
    protected $dateFormat    = 'datetime';
    protected $createdField  = 'created_at';
    protected $updatedField  = 'updated_at';
    protected $deletedField  = 'deleted_at';

    // Validation
    protected $validationRules      = [];
    protected $validationMessages   = [];
    protected $skipValidation       = false;
    protected $cleanValidationRules = true;

    // Callbacks
    protected $allowCallbacks = true;
    protected $beforeInsert   = [];
    protected $afterInsert    = [];
    protected $beforeUpdate   = [];
    protected $afterUpdate    = [];
    protected $beforeFind     = [];
    protected $afterFind      = [];
    protected $beforeDelete   = [];
    protected $afterDelete    = [];

    /**
     * 增加錢包餘額 用 type 判斷是儲值還是補償
     *
     * @param integer $u_key
     * @param string $type
     * @param integer $balance
     * @param integer $addAmount
     * @param string|null $o_key
     * @return boolean
     */
    public function addBalanceTranscation(int $u_key, string $type, int $balance, int $addAmount, ?string $o_key = null): bool
    {
        try {
            $this->db->transStart();

            $history = [
                "u_key"  => $u_key,
                "o_key"  => $o_key,
                "type"   => $type,
                "amount" => $addAmount,
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ];

            $this->db->table("history")
                     ->insert($history);

            $wallet = [
                "balance" => $balance + $addAmount
            ];

            $this->db->table("wallet")
                     ->where("u_key",$u_key)
                     ->update($wallet);

            $result = $this->db->transComplete();
            return $result;
        } catch (\Exception $e) {
            log_message('error', '[ERROR] {exception}', ['exception' => $e]);
            return false;
        }
        return true;
    }

    /**
     * 使用者錢包扣款
     *
     * @param integer $u_key
     * @param string $o_key
     * @param string $type
     * @param integer $nowAmount
     * @param integer $total
     * @return boolean
     */
    public function chargeTransaction(int $u_key, string $o_key, string $type, int $nowAmount, int $total): bool
    {
        $history = [
            "u_key"  => $u_key,
            "type"   => $type,
            "amount" => $total,
            "o_key"  => $o_key,
            "created_at" => date("Y-m-d H:i:s"),
            "updated_at" => date("Y-m-d H:i:s")
        ];

        try {
            $this->db->transBegin();

            $this->db->table("history")
                     ->insert($history);

            $wallet = [
                "balance" => $nowAmount - $total,
                "updated_at" => date("Y-m-d H:i:s")
            ];

            $this->db->table("wallet")
                ->where("u_key", $u_key)
                ->where("balance >=", $total)
                ->update($wallet);

            if ($this->db->transStatus() === false || $this->db->affectedRows() == 0) {
                $this->db->transRollback();
                return false;
            } else {
                $this->db->transCommit();
                return true;
            }
        } catch (\Exception $e) {
            log_message('error', '[ERROR] {exception}', ['exception' => $e]);
            return false;
        }
        return true;
    }
}
