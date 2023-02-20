#!/bin/bash

DEBUG=0

function json_is_debug_mode() {
    if (( $DEBUG==1 )); then
        return 0;
    else
        return 1;
    fi
}

function json_get_value() {
    local p_json_file=$1
    local p_key=$2
    local p_pos=$3

    if json_is_debug_mode; then
        echo ""
        echo "== json_get_value =="
        echo "p_json_file :$p_json_file"
        echo "p_key       :$p_key"
        echo "p_pos       :$p_pos"
        echo ""
    fi

    local key=$p_key
    local count=$(grep -c "\"$key\"\s*:" ${p_json_file})
    local pos=1
    if [[ -n "$pos" ]]; then
        if (( p_pos > count)); then
            pos=$count
        elif (( p_pos > 0)); then
            pos=$p_pos
        fi
    fi

    if ((count<1)); then
        echo "null"
        return 1
    fi

    local row_content=$(grep "\"$key\"\s*:" ${p_json_file} | awk -v p=$pos '{if(NR==p){print $0}}')

    local left_content=$(echo $row_content | grep -o -E "\"$key\"\s*:")
    local key_and_value=$(echo $row_content | grep -o -E "\"$key\"\s*:\s*\".+\"")

    local is_string=$(echo $key_and_value | grep -E -c "\"$")
    if [[ $is_string -eq 0 ]]; then
        # 非字符型号
        key_and_value=$(echo $row_content | grep -o -E "\"$key\"\s*:\s*\S+")

        # 删除末尾的逗号
        key_and_value=$(echo $key_and_value | sed 's/\s*,$//')
    fi

    # 返回值, 不删除两边双引号, 因为会导致值的两边空格丢失
    local return_value=$(echo $key_and_value | sed "s/$left_content\s*//")

    if json_is_debug_mode; then
        # echo "row_content   |${row_content}|"
        # echo "is_string     |${is_string}|"
        # echo "left_content  |${left_content}|"
        # echo "key_and_value |${key_and_value}|"
        # echo ""
        echo "return_value  |${return_value}|"
    else
        echo $return_value
    fi
}

# 修改 json 文件
# 1. 只可以修改值为非对象或数组的字段
# 2. key 与 value 必须在同一行
# 3. 如果有多个重复 key, 需要指定第几次出现的值, 默认为第一次的值
function json_set_value(){
    local p_json_file=$1
    local p_key=$2
    local p_value=$3
    local p_pos=$4

    if json_is_debug_mode; then
        echo ""
        echo "== json_set_value =="
        echo "p_json_file :$p_json_file"
        echo "p_key     :$p_key"
        echo "p_value   :$p_value"
        echo "p_pos     :$p_pos"
        echo ""
    fi

    local key=$p_key
    local count=$(grep -c "\"$key\"\s*:" ${p_json_file})
    local pos=1
    if [[ -n "$pos" ]]; then
        if (( p_pos > count)); then
            pos=$count
        elif (( p_pos > 0)); then
            pos=$p_pos
        fi
    fi

    if ((count<1)); then
        echo -e "ERROR: 没找到 Key: $key\n"
        return 1
    fi

    local full_string=$(grep -n "\"$key\"\s*:" ${p_json_file} | awk -v p=$pos '{if(NR==p){print $0}}')
    local row_number=${full_string%%:*}
    local row_content=${full_string#*:}

    local left_content=$(echo $row_content | grep -o -E "\"$key\"\s*:")
    local key_and_value=$(echo $row_content | grep -o -E "\"$key\"\s*:\s*\".+\"")
    local new_value_tmp=$p_value

    local is_string=$(echo $key_and_value | grep -E -c "\"$")
    if [[ $is_string -gt 0 ]]; then
        # 字符型
        new_value_tmp="\"$p_value\""
    else
        # 非字符型号
        key_and_value=$(echo $row_content | grep -o -E "\"$key\"\s*:\s*\S+")
        # 删除末尾的逗号
        key_and_value=$(echo $key_and_value | sed 's/\s*,$//')
    fi
    local new_key_value=$(echo "$left_content $new_value_tmp")

    if json_is_debug_mode; then
        # echo "full_string   |${full_string}|"
        # echo "row_number    |${row_number}|"
        # echo "is_string     |${is_string}|"
        # echo "row_content   |${row_content}|"
        # echo "left_content  |${left_content}|"
        # echo "key_and_value |${key_and_value}|"
        # echo "new_key_value |${new_key_value}|"
        # echo ""
        nl ${p_json_file} | sed -n "${row_number}p"
    fi

    sed -i "${row_number}s|$key_and_value|${new_key_value}|" ${p_json_file}

    if json_is_debug_mode; then
        nl ${p_json_file} | sed -n "${row_number}p"
    fi

    return 0
}

function json_test_read(){
    DEBUG=1
    echo -e "\n\n\n\n\n\n\n\n"

    temp_json_file=/etc/v2ray/tmp_config.json

    if [ ! -f $temp_json_file ]; then
        echo "ERROR: 文件不存在 $temp_json_file"
    fi

    json_get_value $temp_json_file 'certificateFile'  1
    json_get_value $temp_json_file 'certificateFile'  2
    json_get_value $temp_json_file 'keyFile'
    json_get_value $temp_json_file 'id'
    json_get_value $temp_json_file 'path'
    json_get_value $temp_json_file 'alterId'
    json_get_value $temp_json_file 'port'
    
    DEBUG=0
}

function json_test_write(){
    DEBUG=1
    echo -e "\n\n\n\n\n\n\n\n"
    org_json=/etc/v2ray/config.json
    temp_json_file=/etc/v2ray/tmp_config.json
    rm -rf $temp_json_file
    cp -f $org_json $temp_json_file

    json_set_value $temp_json_file 'certificateFile' '7777777 =' 1
    json_set_value $temp_json_file 'certificateFile' '8888888 %' 2
    json_set_value $temp_json_file 'keyFile' '99999='
    json_set_value $temp_json_file 'id' 'id-id-id-id'
    json_set_value $temp_json_file 'path' '/aaaaaaaaaaaaaaaaa/'
    json_set_value $temp_json_file 'alterId' '666'
    json_set_value $temp_json_file 'port' '444'
    # nl ${temp_json_file}
    
    DEBUG=0
}

case $1 in
test_mode)
    if [ -n $2 ]; then
        export DEBUG=$2
    else
        export DEBUG=1
    fi
;;
json_test_write)
    json_test_write
;;
json_test_read)
    json_test_read
;;
esac
