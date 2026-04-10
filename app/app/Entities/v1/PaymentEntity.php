<?php

namespace App\Entities\v1;

use CodeIgniter\Entity\Entity;

class PaymentEntity extends Entity
{
    /**
     * 訂單付款主鍵
     *
     * @var int
     */
    protected $p_key;

    /**
     * 使用者外來鍵
     *
     * @var int
     */
    protected $u_key;

    /**
     * 訂單外來鍵
     *
     * @var string
     */
    protected $o_key;

    /**
     * 訂單外來鍵
     *
     * @var int
     */
    protected $h_key;

    /**
     * 訂單付款總價
     *
     * @var int
     */
    protected $total;

    /**
     * 建立時間
     *
     * @var string
     */
    protected $createdAt;

    /**
     * 最後更新時間
     *
     * @var string
     */
    protected $updatedAt;

    /**
     * 刪除時間
     *
     * @var string
     */
    protected $deletedAt;

    protected $datamap = [
        'createdAt' => 'created_at',
        'updatedAt' => 'updated_at',
        'deletedAt' => 'deleted_at'
    ];

    protected $casts = [
        'p_key' => 'integer'
    ];

    protected $dates = []; 
}
