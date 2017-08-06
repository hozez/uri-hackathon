$(document).ready(function() {
    var SERVER = 'http://localhost:8080';

    $('#action--scan').on('click', onScanClick);
    $('#action--clear').on('click', onClearClick);
    $('#action--copy').on('click', onCopyClick);

    $('body').on('change','.result .list input:checkbox', onResultChecked);

    function onScanClick() {
        var text = $('#data--text').text();
        sendRequest(text);
    }

    function sendRequest(text) {
        var dataToSend = {
            text: text
        };

        preRequestClean();

        setLoadingState();

        $('.preloader-wrapper').addClass('active');
        $('.preloader-wrapper').fadeIn();

        $.ajax({
            type: "POST",
            url: SERVER + '/analyze_sentence',
            data: JSON.stringify(dataToSend),
            success: onRequestResponse,
            contentType: 'application/json',
            dataType: 'json'
        });
    }

    function onRequestResponse(response) {
        var newText = $('#data--text').html();
        $('.result .title').text(response.iocs_count + ' IoC' + (response.iocs_count > 1 ? 's' : '') + ' found');

        response.iocs.forEach(function(ioc, index) {
            $('.result .list').append('<p><input type="checkbox" id="result_' + index + '" value="' + ioc + '" checked/><label for="result_' + index + '" title="' + ioc + '">' + ioc + '</label></p>');
            newText = highlightWord(newText, ioc);
        });
       
        $('#data--text').html(newText);

        if (response.iocs_count > 0) {
            $('#action--copy').show();
        }

        setPostLoadingState();
    }

    function onClearClick() {
        $('#data--text').html('');
        preRequestClean();
    }

    function highlightWord(text, word) {
        var wordWithoutSpecialChar = word;
        wordWithoutSpecialChar = wordWithoutSpecialChar.replace(/\\/g, '\\\\');
        wordWithoutSpecialChar = wordWithoutSpecialChar.replace(/\./g, '\.');

        var regex = new RegExp(wordWithoutSpecialChar, 'gi');
 
        return text.replace(regex, '<span class="highlight">' + word + '</span>');
    }

    function preRequestClean() {
        $('.result .list').html('');
        $('.result .title').text('0 IoC found');
        $('#data--text .highlight').removeClass('highlight');
        $('#action--copy').hide();
    }

    function setLoadingState() {
        $('#action--scan').addClass('disabled');
        $('#action--clear').addClass('disabled');
        $('#data--text').attr('contenteditable', false);
    }

    function setPostLoadingState() {
        $('.preloader-wrapper').fadeOut();
        $('#action--scan').removeClass('disabled');
        $('#action--clear').removeClass('disabled');
        $('#data--text').attr('contenteditable', true);
    }

    function onCopyClick() {
        var textToCopy = [];

        $('.result .list input:checkbox:checked').toArray().forEach(function(item) {
            textToCopy.push(item.value);
        });

        copyToClipboard(textToCopy.join('\n'));
        Materialize.toast(textToCopy.length + ' item' + (textToCopy.length > 1 ? 's' : '') + ' copied', 4000)
    }

    function copyToClipboard(text) {
        $('#clipboard').show();
        $('#clipboard').val(text);

        $('#clipboard').select();
        document.execCommand('copy');
        $('#clipboard').hide();
    }

    function onResultChecked() {
        if ($('.result .list input:checkbox:checked').toArray().length > 0) {
            $('#action--copy').show();
        } else {
            $('#action--copy').hide();
        }
    }
});