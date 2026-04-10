<?php

namespace App\Models\v1;

use CodeIgniter\Model;

use App\Entities\v1\PaymentEntity;

class PaymentModel extends Model
{
    protected $DBGroup          = USE_DB_GROUP;
    protected $table            = 'payment';
    protected $primaryKey       = 'p_key';
    protected $useAutoIncrement = true;
    protected $insertID         = 0;
    protected $returnType       = PaymentEntity::class;
    protected $useSoftDeletes   = true;
    protected $protectFields    = true;
    protected $allowedFields    = ['p_key','u_key','o_key','h_key', 'total'];

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
     * 新增付款 transcation
     *
     * @param integer $u_key
     * @param string $o_key
     * @param integer $total
     * @param integer $nowAmount
     * @param string $type
     * @return bool
     */
    public function createPaymentTranscation(int $u_key, string $o_key, int $total, int $nowAmount, string $type): bool
    {
        $history = [
            "u_key" => $u_key,
            "type"  => $type,
            "amount" => $total,
            "created_at" => date("Y-m-d H:i:s"),
            "updated_at" => date("Y-m-d H:i:s")
        ];
        
        try {
            $this->db->transBegin();

            $this->db->table("history")
                     ->insert($history);

            $historyInsertKey = $this->db->insertID();

            $paymentData = [
                "u_key" => $u_key,
                "h_key" => $historyInsertKey,
                "o_key" => $o_key,
                "total" => $total,
                "created_at" => date("Y-m-d H:i:s"),
                "updated_at" => date("Y-m-d H:i:s")
            ];

            $this->db->table("payment")
                     ->insert($paymentData);

            $wallet = [
                "balance" => $nowAmount - $total,
                "updated_at" => date("Y-m-d H:i:s")
            ];

            $this->db->table("wallet")
                     ->where("u_key",$u_key)
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
    }

    /**
     * 刪除訂單付款與流水帳 transcation
     *
     * @param integer $p_key
     * @param integer $h_key
     * @return boolean
     */
    public function deletePaymentTranscation(int $p_key, int $h_key): bool
    {
        try {
            $this->db->transStart();

            $time = [
                "deleted_at" => date("Y-m-d H:i:s")
            ];

            $this->db->table("history")
                     ->where("h_key", $h_key)
                     ->update($time);

            $this->db->table("payment")
                     ->where("p_key", $p_key)
                     ->update($time);

            $result = $this->db->transComplete();
            return $result;
        } catch (\Exception $e) {
            log_message('error', '[ERROR] {exception}', ['exception' => $e]);
            return false;
        }
    }

    /**
     * 刪除訂單付款與流水帳 dtm transcation
     *
     * @param string  $o_key
     * @param integer $h_key
     * @return boolean
     */
    public function deleteDtmPaymentTranscation(string $o_key, int $h_key): bool
    {
        try {
            $this->db->transStart();

            $time = [
                "deleted_at" => date("Y-m-d H:i:s")
            ];

            $this->db->table("history")
                     ->where("h_key", $h_key)
                     ->update($time);

            $this->db->table("payment")
                     ->where("o_key", $o_key)
                     ->update($time);

            $result = $this->db->transComplete();
            return $result;
        } catch (\Exception $e) {
            log_message('error', '[ERROR] {exception}', ['exception' => $e]);
            return false;
        }
    }
}
