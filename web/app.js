$(document).ready(function() {
    var SERVER = 'http://localhost:8080';

    $('#action--scan').on('click', onScanClick);
    $('#action--clear').on('click', onClearClick);

    function onScanClick() {
        var text = $('#data--text').text();
        sendRequest(text);
    }

    function sendRequest(text) {
        var dataToSend = {
            text: text
        };

        preRequestClean();

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


        response.iocs.forEach(function(ioc) {
            $('.result ul').append('<li>' + ioc + '</li>')
            newText = highlightWord(newText, ioc);
        });
       
        $('#data--text').html(newText);

        $('.preloader-wrapper').fadeOut();
    }

    function onClearClick() {
        $('#data--text').html('');
        preRequestClean();
    }

    function highlightWord(text, word) {
        var regex = new RegExp(word, 'gi');
 
        return text.replace(regex, '<span class="highlight">' + word + '</span>');
    }

    function preRequestClean() {
        $('.result ul').html('');
        $('.result .title').text('0 IoC found');
        $('#data--text .highlight').removeClass('highlight');
    }
});