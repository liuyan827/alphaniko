const bitcoin = require('bitcoinjs-lib');
const crypto = require('crypto');
const cluster = require('cluster');
const os = require('os');
const redis = require('redis');
const { promisify } = require('util');

class BTCOS_L2_Protocol {
    constructor(senderPrivateKey, receiverPublicKey) {
        this.senderPrivateKey = senderPrivateKey;
        this.receiverPublicKey = receiverPublicKey;
        this.gasTokenTotalSupply = 1000000; // 设定 gas 代币的总发行量为 1,000,000 个
        this.gasTokenBalance = {}; // gas 代币余额表，每个地址对应的余额

        // 初始化 Redis 客户端
        this.redisClient = redis.createClient();
        this.getAsync = promisify(this.redisClient.get).bind(this.redisClient);
        this.setAsync = promisify(this.redisClient.set).bind(this.redisClient);
    }

    // 开通通道
    openChannel(senderAddress, receiverAddress, fundingAmount, gasTokenAmount) {
        console.log(`Channel opened between ${senderAddress} and ${receiverAddress} with ${fundingAmount} satoshis and ${gasTokenAmount} QUICK tokens on the BTCOS network.`);
        // 在通道开通时，将 gas 代币分配给发送方地址
        this.gasTokenBalance[senderAddress] = gasTokenAmount;
        console.log(`Gas token balance for ${senderAddress}: ${this.gasTokenBalance[senderAddress]}`);
        // 这里可以添加开通通道的逻辑
    }

    /**
     * 创建并签名支付请求
     * @param {string} senderAddress - 发送方地址
     * @param {number} amount - 转账金额
     * @param {number} gasFee - Gas 费用
     * @param {number} gasTokenAmount - Gas 代币数量
     * @returns {string} - 签名的支付请求的十六进制表示
     */
    createAndSignPaymentRequest(senderAddress, amount, gasFee, gasTokenAmount) {
        const totalAmount = amount + gasFee; // 总支付金额（包括 gas 费用）
        const tx = new bitcoin.TransactionBuilder();
        
        // 添加输入
        tx.addInput('9ac86d1e3b18ff61c193bb2b5e9f548b82f2fd96e0b6b7f0f3e1a4be6bde15e2', 0);
        
        // 添加输出（转账金额）
        tx.addOutput(this.receiverPublicKey, amount);

        // 添加输出（gas 代币）
        tx.addOutput(this.senderPrivateKey, gasTokenAmount);

        // 使用发送方私钥进行签名
        const keyPair = bitcoin.ECPair.fromWIF(this.senderPrivateKey);
        tx.sign(0, keyPair);

        // 更新 gas 代币余额
        if (!this.gasTokenBalance[senderAddress]) {
            this.gasTokenBalance[senderAddress] = 0;
        }
        this.gasTokenBalance[senderAddress] += gasTokenAmount;

        // 将支付请求记录到 Redis 中，以防止重放攻击
        this.setAsync(senderAddress, true, 'EX', 3600); // 设置过期时间为 1 小时

        // 构建并返回签名的支付请求的十六进制表示
        const rawTx = tx.build().toHex();
        console.log('Payment request created and signed:', rawTx);
        return rawTx;
    }

    // 验证支付请求
    async verifyPaymentRequest(paymentRequest, senderAddress) {
        // 检查支付请求是否已经处理过
        const isProcessed = await this.getAsync(senderAddress);
        if (isProcessed) {
            throw new Error('Payment request has already been processed.');
        }

        const txParsed = bitcoin.Transaction.fromHex(paymentRequest);
        const publicKeySender = bitcoin.ECPair.fromPublicKeyBuffer(txParsed.ins[0].script.chunks[1]);
        console.log('Transaction signature valid:', txParsed.verify(0, publicKeySender));
        console.log(`Payment received from ${senderAddress}.`);
        // 这里可以添加接收方验证支付请求的逻辑
    }

    // 内存硬币工作量证明
    memoryHardProofOfWork(data, nonce, difficulty) {
        const input = data + nonce;
        const hash = crypto.scryptSync(input, 'salt', { N: 16384, r: 8, p: 1 }); // 使用 scrypt 算法，N 参数表示内存大小，这里设为 16384，即 16GB
        const leadingZeros = hash.toString('hex').match(/^0+/);
        const leadingZerosCount = leadingZeros ? leadingZeros[0].length : 0;
        return leadingZerosCount >= difficulty;
    }

    // 发送方 gas 代币余额
    async getGasTokenBalance(senderAddress) {
        // 从 Redis 中获取 gas 代币余额
        const balance = await this.getAsync(senderAddress);
        return balance || 0;
    }

    // 总发行 gas 代币数量
    getGasTokenTotalSupply() {
        return this.gasTokenTotalSupply;
    }
}

// 如果是主进程，创建子进程处理请求
if (cluster.isMaster) {
    const numWorkers = os.cpus().length;
    for (let i = 0; i < numWorkers; i++) {
        cluster.fork();
    }
} else {
    // 创建 BTCOS_L2_Protocol 的实例
    const btcosProtocol = new BTCOS_L2_Protocol();

    // 处理请求的示例代码
    const paymentRequest = btcosProtocol.createAndSignPaymentRequest(senderAddress, amount, gasFee, gasTokenAmount);
    btcosProtocol.verifyPaymentRequest(paymentRequest, senderAddress);
}

module.exports = BTCOS_L2_Protocol;
